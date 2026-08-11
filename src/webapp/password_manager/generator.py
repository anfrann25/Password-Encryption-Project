"""
Password *generation* from a memorable seed.

Αυτό δεν είναι το ίδιο πράγμα με το vault (:mod:`.models`): εκεί ο
στόχος είναι να θυμηθούμε αργότερα ένα συγκεκριμένο plaintext. Εδώ ο
στόχος είναι το αντίθετο -- να παράξουμε ένα καινούριο,
τυχαίο-φαινομενικά string, χρησιμοποιώντας το ίδιο crypto pipeline
(Algorithm A/B chain, βλ. :mod:`.crypto`) σαν one-way PRF: ίδιο seed +
διαφορετικό τυχαίο εφήμερο κλειδί/pattern κάθε φορά -> εντελώς
διαφορετικό αποτέλεσμα, χωρίς σχέση με προηγούμενα.

Σημαντικό: αφού το εφήμερο κλειδί δεν αποθηκεύεται ΠΟΥΘΕΝΑ (πετιέται
αμέσως μετά τη χρήση του), δεν υπάρχει τρόπος να ξαναπαραχθεί το ίδιο
generated string από το ίδιο seed. Αυτό είναι σκόπιμο -- βλ. το README
της webapp για το γιατί -- και είναι και ο λόγος που το seed δεν
ελέγχεται καθόλου για "δύναμη" (:func:`.functions.password_requirements`):
δεν είναι αυτό που καταλήγει να χρησιμοποιείται σαν κωδικός, είναι απλά
μια βολική είσοδος για τον generator.

Αφού ο χρήστης διαλέξει ένα από τα προτεινόμενα strings, ΑΥΤΟ (και μόνο
αυτό) αποθηκεύεται στο vault σαν κανονική εγγραφή --
``models.Password.encrypt(chosen, pattern, master_key, name)`` -- με τον
ίδιο ακριβώς μηχανισμό που χρησιμοποιεί και η χειροκίνητη φόρμα "Νέα
εγγραφή". Αυτό το module δεν αγγίζει καθόλου τη μόνιμη αποθήκευση.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import crypto
from .functions import decimal_to_binary, get_random_number

SEPARATOR = "!"
EPHEMERAL_KEY_BYTES = 32


def random_pattern() -> str:
    """Τυχαίο binary pattern (1-50 -> 6-bit), ίδια λογική με
    ``app._generate_pattern()`` / το CLI's "give a number 1-50" flow.
    """
    number = get_random_number(49) + 1
    random_value = get_random_number(number) + number
    if random_value > 50:
        random_value -= number
    return decimal_to_binary(random_value)


def format_candidate(raw_hex: str, length: int | None, use_separator: bool) -> str:
    """Apply display/format options to a raw hex string.

    Args:
        raw_hex: Hex-encoded ciphertext bytes -- already alphanumeric
            (``[0-9a-f]``) on its own.
        length: If given and positive, truncate the *final* string
            (after any separator insertion) to this many characters.
            ``None`` means "no truncation". Truncation can only shorten
            towards what the seed's byte-length produced -- a longer
            seed gives more hex characters to work with.
        use_separator: Whether to insert :data:`SEPARATOR` at the
            midpoint, same convention as
            :meth:`.models.Password.encrypt`. Leave this off for sites
            that reject non-alphanumeric characters -- hex digits alone
            are already letters+digits.
    """
    formatted = raw_hex
    if use_separator:
        mid = len(formatted) // 2
        formatted = formatted[:mid] + SEPARATOR + formatted[mid:]
    if length is not None and length > 0:
        formatted = formatted[:length]
    return formatted


@dataclass
class Candidate:
    """One generated-password suggestion.

    Nothing about how it was derived (pattern, ephemeral key) is kept
    -- there would be no way to use that to reproduce it anyway, since
    the ephemeral key is never retained. Only ``text`` matters, and
    only until the user either picks it (it then gets vault-encrypted
    like any manual entry) or discards it.
    """

    text: str


def generate_candidates(
    seed: str,
    count: int = 3,
    length: int | None = None,
    use_separator: bool = True,
) -> list[Candidate]:
    """Produce `count` independent generated-password suggestions from `seed`.

    Each candidate uses its own fresh random pattern *and* fresh random
    32-byte ephemeral key -- unrelated to the vault's master key, and
    discarded immediately after use. That's why the same seed gives a
    different result every time, including across the `count`
    candidates produced by one call.

    Args:
        seed: Anything easy to remember (e.g. ``"andreas123"``). Never
            validated for strength and never stored anywhere.
        count: How many independent suggestions to produce.
        length: Optional max length for each formatted suggestion.
        use_separator: Whether each suggestion includes the ``!`` separator.

    Returns:
        A list of `count` :class:`Candidate` objects.

    Raises:
        ValueError: If `seed` is empty.
    """
    if not seed:
        raise ValueError("seed must not be empty")

    candidates: list[Candidate] = []
    for _ in range(count):
        pattern = random_pattern()
        ephemeral_key = secrets.token_bytes(EPHEMERAL_KEY_BYTES)
        cipher_bytes = crypto.encrypt(seed, pattern, ephemeral_key)
        formatted = format_candidate(cipher_bytes.hex(), length, use_separator)
        candidates.append(Candidate(text=formatted))
    return candidates
