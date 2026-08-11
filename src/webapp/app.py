#!/usr/bin/env python3
"""
Local web UI for the Password Manager.

Αυτό το αρχείο ΔΕΝ αγγίζει καθόλου τη λογική κρυπτογράφησης: χρησιμοποιεί
ακριβώς τα ίδια modules (crypto.py, master.py, database.py, models.py) που
χρησιμοποιεί το CLI (cli.py). Λειτουργεί απλά ως εναλλακτικό "front-end":
αντί για terminal prompts, εμφανίζει HTML φόρμες.

Χρήση:

    python3 app.py                     # χρησιμοποιεί ./database.db
    python3 app.py /path/to/database.db

Άνοιξε http://127.0.0.1:5000 στον browser σου.

Ο master key ΔΕΝ αποθηκεύεται ποτέ σε cookie -- κρατιέται μόνο σε μνήμη
στον server (SESSIONS dict), κλειδωμένος με ένα τυχαίο session id που
μπαίνει σε httponly cookie. Έτσι ο browser δεν βλέπει ποτέ το raw κλειδί.
"""

from __future__ import annotations

import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, redirect, render_template, request, session, url_for

sys.path.insert(0, str(Path(__file__).parent))

from password_manager import database, generator, master  # noqa: E402
from password_manager.functions import (  # noqa: E402
    decimal_to_binary,
    get_random_number,
    password_requirements,
)
from password_manager.models import Password  # noqa: E402

GENERATE_LENGTH_CHOICES = [12, 16, 20, 24, 32]

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # νέο κάθε φορά που ξεκινά ο server

# db_path -> sqlite3 connection is opened per-request (see get_connection)
DB_PATH = sys.argv[1] if len(sys.argv) > 1 else "database.db"

# In-memory store: session_id -> master_key (bytes). ΠΟΤΕ σε cookie/DB.
SESSIONS: dict[str, bytes] = {}

MAX_LOGIN_ATTEMPTS = 3


def get_connection():
    import sqlite3

    return sqlite3.connect(DB_PATH)


def current_master_key() -> bytes | None:
    sid = session.get("sid")
    if not sid:
        return None
    return SESSIONS.get(sid)


def require_login():
    """Redirect to /login if there is no verified master key in memory."""
    if current_master_key() is None:
        return redirect(url_for("login"))
    return None


def _generate_pattern() -> str:
    """Server-side equivalent of the CLI's 'give a number 1-50' flow.

    Στο CLI ο χρήστης έδινε έναν αριθμό χειροκίνητα -- εδώ, αφού ο
    αριθμός είναι απλά καλλωπιστικός επιλογέας του Algorithm A/B chain
    (η πραγματική ασφάλεια έρχεται από τον master key + το per-entry
    salt), τον παράγουμε αυτόματα με την ίδια λογική.
    """
    number = get_random_number(49) + 1  # 1..50
    binary = decimal_to_binary(number)
    random_value = get_random_number(number) + number
    if random_value > 50:
        random_value -= number
    pattern = decimal_to_binary(random_value)
    return pattern


_HEX_DIGITS = set("0123456789abcdefABCDEF")


def _validate_import_row(raw: object) -> str | None:
    """Sanity-check one entry from an imported JSON file.

    Δεν προσπαθεί να κάνει decrypt -- αυτό θα απαιτούσε τον master key
    που δημιούργησε το export, που μπορεί κάλλιστα να είναι διαφορετικός
    από τον τρέχοντα (π.χ. import σε άλλη μηχανή/βάση). Ελέγχει μόνο ότι
    το σχήμα είναι αυτό που περιμένουμε, ώστε ένα κακοφτιαγμένο αρχείο
    να μην καταλήξει σε άχρηστες γραμμές στη βάση.

    Returns:
        ``None`` αν η γραμμή είναι έγκυρη, αλλιώς ένα σύντομο μήνυμα
        για το πρόβλημα.
    """
    if not isinstance(raw, dict):
        return "δεν είναι JSON object"
    for field in ("pattern", "salt", "ciphertext"):
        value = raw.get(field)
        if not isinstance(value, str) or not value:
            return f"λείπει ή είναι κενό το πεδίο '{field}'"
    if any(bit not in "01" for bit in raw["pattern"]):
        return "το 'pattern' πρέπει να είναι binary string (μόνο 0/1)"
    if any(c not in _HEX_DIGITS for c in raw["salt"]):
        return "το 'salt' πρέπει να είναι hex"
    if any(c not in _HEX_DIGITS and c != "!" for c in raw["ciphertext"]):
        return "το 'ciphertext' πρέπει να είναι hex (με προαιρετικό '!')"
    if not isinstance(raw.get("name", ""), str):
        return "το 'name' πρέπει να είναι string"
    return None


def _validate_master_block(raw: object) -> str | None:
    """Sanity-check the optional ``"master"`` block of an import file."""
    if not isinstance(raw, dict):
        return "το πεδίο 'master' δεν είναι JSON object"
    salt = raw.get("salt")
    verifier = raw.get("verifier")
    iterations = raw.get("iterations")
    if not isinstance(salt, str) or any(c not in _HEX_DIGITS for c in salt):
        return "το 'master.salt' πρέπει να είναι hex string"
    if not isinstance(verifier, str) or any(c not in _HEX_DIGITS for c in verifier):
        return "το 'master.verifier' πρέπει να είναι hex string"
    if not isinstance(iterations, int) or iterations <= 0:
        return "το 'master.iterations' πρέπει να είναι θετικός ακέραιος"
    return None


@app.route("/", methods=["GET"])
def index():
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    return redirect(url_for("entries_view"))


@app.route("/login", methods=["GET", "POST"])
def login():
    conn = get_connection()
    try:
        database.create_table(conn)
        database.create_settings_table(conn)
        settings = database.get_master_settings(conn)
        is_setup = settings is None

        error = None
        if request.method == "POST":
            if is_setup:
                first = request.form.get("password", "")
                second = request.form.get("confirm", "")
                if not first:
                    error = "Ο master password δεν μπορεί να είναι κενός."
                elif first != second:
                    error = "Οι κωδικοί δεν ταιριάζουν."
                else:
                    salt = master.generate_salt()
                    master_key = master.derive_master_key(first, salt)
                    verifier = master.make_verifier(master_key)
                    database.save_master_settings(
                        conn, salt.hex(), master.PBKDF2_ITERATIONS, verifier.hex()
                    )
                    sid = secrets.token_hex(16)
                    SESSIONS[sid] = master_key
                    session["sid"] = sid
                    return redirect(url_for("entries_view"))
            else:
                attempts = session.get("attempts", 0)
                password = request.form.get("password", "")
                salt_hex, iterations, verifier_hex = settings
                salt = bytes.fromhex(salt_hex)
                expected_verifier = bytes.fromhex(verifier_hex)
                master_key = master.derive_master_key(password, salt, iterations)
                if master.verify(master_key, expected_verifier):
                    sid = secrets.token_hex(16)
                    SESSIONS[sid] = master_key
                    session["sid"] = sid
                    session.pop("attempts", None)
                    return redirect(url_for("entries_view"))
                attempts += 1
                session["attempts"] = attempts
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    session.pop("attempts", None)
                    error = "Υπερβολικές αποτυχημένες προσπάθειες."
                else:
                    remaining = MAX_LOGIN_ATTEMPTS - attempts
                    error = f"Λάθος master password ({remaining} απόμειναν προσπάθειες)."

        return render_template(
            "login.html", is_setup=is_setup, error=error, db_path=DB_PATH
        )
    finally:
        conn.close()


@app.route("/logout", methods=["POST"])
def logout():
    sid = session.pop("sid", None)
    if sid:
        SESSIONS.pop(sid, None)
    return redirect(url_for("login"))


@app.route("/entries", methods=["GET"])
def entries_view():
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    conn = get_connection()
    try:
        entries = database.load_users(conn)
    finally:
        conn.close()
    revealed_id = session.pop("revealed_id", None)
    revealed_plain = session.pop("revealed_plain", None)
    return render_template(
        "entries.html",
        entries=list(enumerate(entries)),
        db_path=DB_PATH,
        revealed_id=revealed_id,
        revealed_plain=revealed_plain,
    )


@app.route("/entries/new", methods=["POST"])
def entries_new():
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    master_key = current_master_key()

    name = request.form.get("name", "").strip()
    plaintext = request.form.get("password", "")

    problems = password_requirements(plaintext)
    if not name:
        problems.insert(0, "ένα όνομα για την εγγραφή")

    if problems:
        conn = get_connection()
        try:
            entries = database.load_users(conn)
        finally:
            conn.close()
        return render_template(
            "entries.html",
            entries=list(enumerate(entries)),
            db_path=DB_PATH,
            problems=problems,
            form_name=name,
        )

    pattern = _generate_pattern()
    entry = Password.encrypt(plaintext, pattern, master_key, name)

    conn = get_connection()
    try:
        database.insert_user(conn, entry.name, entry.key, entry.salt, entry.ciphertext)
    finally:
        conn.close()

    return redirect(url_for("entries_view"))


@app.route("/generate", methods=["GET"])
def generate_view():
    """"Δημιουργία κωδικού": ξεχωριστό mode από τη χειροκίνητη φόρμα.

    Ο χρήστης δίνει ένα εύκολο-να-θυμάται seed (χωρίς κανέναν έλεγχο
    δύναμης -- δεν αποθηκεύεται ποτέ όπως-είναι) και βλέπει 3
    προτεινόμενα, φαινομενικά-τυχαία strings παραγμένα από αυτό. Αν
    ήρθε εδώ πατώντας "Αναδημιουργία" σε υπάρχουσα εγγραφή, το ?replace_index
    προεπιλέγει το όνομα και κάνει το "Αποθήκευση" να αντικαταστήσει
    εκείνη την εγγραφή αντί να προσθέσει καινούρια.
    """
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp

    replace_index = request.args.get("replace_index", "")
    prefill_name = request.args.get("name", "")
    return render_template(
        "generate.html",
        db_path=DB_PATH,
        length_choices=GENERATE_LENGTH_CHOICES,
        replace_index=replace_index,
        form_name=prefill_name,
        candidates=None,
    )


@app.route("/generate/preview", methods=["POST"])
def generate_preview():
    """Στάδιο 1: παράγει 3 variants από το seed για να διαλέξει ο χρήστης.

    Ούτε το seed ούτε τα variants αποθηκεύονται εδώ -- μόνο εμφανίζονται.
    Το seed περνάει ξανά σαν hidden field στη φόρμα ώστε το κουμπί
    "Νέες προτάσεις" να μπορεί να ζητήσει ένα ακόμα σετ χωρίς να το
    ξαναπληκτρολογήσει ο χρήστης· δεν αποθηκεύεται στο session ή στη βάση.
    """
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp

    seed = request.form.get("seed", "")
    name = request.form.get("name", "").strip()
    replace_index = request.form.get("replace_index", "")
    use_separator = request.form.get("separator") == "on"
    use_uppercase = request.form.get("uppercase") == "on"
    alnum_only = request.form.get("alnum_only") == "on"
    if alnum_only:
        use_separator = False
    length_raw = request.form.get("length", "")
    length = int(length_raw) if length_raw.isdigit() else None

    problems: list[str] = []
    if not seed:
        problems.append("δώσε ένα seed (δεν χρειάζεται να είναι \"ισχυρό\")")
    if not name:
        problems.append("ένα όνομα/χρήση (π.χ. \"Gmail\")")

    candidates = None
    if not problems:
        candidates = generator.generate_candidates(
            seed,
            count=3,
            length=length,
            use_separator=use_separator,
            use_uppercase=use_uppercase,
        )

    return render_template(
        "generate.html",
        db_path=DB_PATH,
        length_choices=GENERATE_LENGTH_CHOICES,
        replace_index=replace_index,
        form_name=name,
        form_seed=seed,
        form_length=length,
        form_separator=use_separator,
        form_uppercase=use_uppercase,
        form_alnum_only=alnum_only,
        candidates=candidates,
        problems=problems or None,
    )


@app.route("/generate/save", methods=["POST"])
def generate_save():
    """Στάδιο 2: ο χρήστης διάλεξε ένα variant -- αποθηκεύεται στο vault
    ακριβώς όπως μια χειροκίνητη εγγραφή (``Password.encrypt``), μόνο
    που το plaintext είναι το generated string αντί για ό,τι θα έγραφε
    ο χρήστης στο πεδίο "Κωδικός" της φόρμας "Νέα εγγραφή".
    """
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    master_key = current_master_key()

    chosen = request.form.get("chosen", "")
    name = request.form.get("name", "").strip()
    replace_index = request.form.get("replace_index", "")

    if not chosen or not name:
        return redirect(url_for("generate_view"))

    pattern = _generate_pattern()
    entry = Password.encrypt(chosen, pattern, master_key, name)

    conn = get_connection()
    try:
        if replace_index.isdigit():
            entries = database.load_users(conn)
            idx = int(replace_index)
            if 0 <= idx < len(entries):
                database.remove_user(conn, entries, entries[idx])
        database.insert_user(conn, entry.name, entry.key, entry.salt, entry.ciphertext)
    finally:
        conn.close()

    return redirect(url_for("entries_view"))


@app.route("/entries/<int:index>/decrypt", methods=["POST"])
def entries_decrypt(index: int):
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    master_key = current_master_key()

    conn = get_connection()
    try:
        entries = database.load_users(conn)
    finally:
        conn.close()

    if 0 <= index < len(entries):
        entry = entries[index]
        try:
            plaintext = entry.decrypt(master_key)
            session["revealed_id"] = index
            session["revealed_plain"] = plaintext
        except ValueError:
            session["revealed_id"] = index
            session["revealed_plain"] = None

    return redirect(url_for("entries_view"))


@app.route("/entries/<int:index>/delete", methods=["POST"])
def entries_delete(index: int):
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp

    conn = get_connection()
    try:
        entries = database.load_users(conn)
        if 0 <= index < len(entries):
            database.remove_user(conn, entries, entries[index])
    finally:
        conn.close()

    return redirect(url_for("entries_view"))


@app.route("/export", methods=["GET"])
def export_entries():
    """Κατεβάζει όλες τις εγγραφές σαν JSON: μόνο name/pattern/salt/ciphertext.

    ΠΟΤΕ το plaintext, ΠΟΤΕ ο master key. Χωρίς τον ίδιο master password
    που δημιούργησε τις εγγραφές, το αρχείο είναι άχρηστο για
    αποκρυπτογράφηση (βλ. ``Password.decrypt``) -- είναι ήδη
    κρυπτογραφημένο περιεχόμενο, οπότε είναι ασφαλές να μετακινείται
    (backup, άλλη μηχανή, cloud storage, κ.λπ.) χωρίς πρόσθετη προστασία.

    Περιλαμβάνει επίσης τα master-password verification settings (salt,
    iterations, verifier -- ΟΧΙ τον ίδιο τον master password) ώστε, αν
    χρειαστεί, το import σε μια ολοκαίνουρια βάση να μπορεί προαιρετικά
    να τα αντιγράψει και το ίδιο typed master password να παράγει το
    ίδιο derived key εκεί -- βλ. :func:`import_entries`.
    """
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp

    conn = get_connection()
    try:
        entries = database.load_users(conn)
        settings = database.get_master_settings(conn)
    finally:
        conn.close()

    payload = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "entries": [
            {
                "name": entry.name,
                "pattern": entry.key,
                "salt": entry.salt,
                "ciphertext": entry.ciphertext,
            }
            for entry in entries
        ],
    }
    if settings is not None:
        salt_hex, iterations, verifier_hex = settings
        payload["master"] = {
            "salt": salt_hex,
            "iterations": iterations,
            "verifier": verifier_hex,
        }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    filename = f"password-manager-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/import", methods=["GET"])
def import_view():
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp
    return render_template("import.html", db_path=DB_PATH, result=None, errors=None)


@app.route("/import", methods=["POST"])
def import_entries():
    """Διαβάζει ένα JSON αρχείο (ίδιας μορφής με το /export) και εισάγει
    τις εγγραφές στην τρέχουσα βάση. Δεν κάνει decrypt τίποτα εδώ --
    απλά αντιγράφει τις ήδη-κρυπτογραφημένες γραμμές.

    Αν προέρχονται από βάση με διαφορετικό (ή απλά διαφορετικά
    παραγμένο) master salt, η "Αποκρυπτογράφηση" θα αποτυγχάνει γι'
    αυτές -- ακόμα κι αν ο χρήστης πληκτρολογήσει το "ίδιο" master
    password, γιατί κάθε βάση παράγει δικό της τυχαίο salt στο πρώτο
    setup, οπότε ίδιο password + διαφορετικό salt = διαφορετικό
    derived key. Το προαιρετικό checkbox "restore_master" αντιμετωπίζει
    ακριβώς αυτό: αντιγράφει το salt/iterations/verifier του exported
    αρχείου στην τρέχουσα βάση, ώστε το ίδιο typed master password να
    παράγει το ίδιο derived key εδώ. Αυτό ΑΚΥΡΩΝΕΙ οποιεσδήποτε
    εγγραφές υπήρχαν ήδη σε αυτή τη βάση πριν το restore (κρυπτογραφημένες
    με το παλιό salt) -- γι' αυτό γίνεται μόνο αν ζητηθεί ρητά, και
    αναγκάζει νέο login αμέσως μετά.
    """
    redirect_resp = require_login()
    if redirect_resp:
        return redirect_resp

    uploaded = request.files.get("file")
    restore_master = request.form.get("restore_master") == "on"
    errors: list[str] = []

    if uploaded is None or uploaded.filename == "":
        errors.append("Διάλεξε ένα αρχείο .json για εισαγωγή.")
        return render_template("import.html", db_path=DB_PATH, result=None, errors=errors)

    try:
        payload = json.loads(uploaded.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"Το αρχείο δεν είναι έγκυρο JSON: {exc}")
        return render_template("import.html", db_path=DB_PATH, result=None, errors=errors)

    raw_entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(raw_entries, list):
        errors.append("Το JSON δεν έχει τη λίστα 'entries' που περιμέναμε.")
        return render_template("import.html", db_path=DB_PATH, result=None, errors=errors)

    master_restored = False
    if restore_master:
        master_block = payload.get("master") if isinstance(payload, dict) else None
        problem = _validate_master_block(master_block)
        if problem:
            errors.append(f"Δεν έγινε restore των master settings: {problem}")
        else:
            conn = get_connection()
            try:
                database.create_settings_table(conn)
                database.overwrite_master_settings(
                    conn, master_block["salt"], master_block["iterations"], master_block["verifier"]
                )
            finally:
                conn.close()
            master_restored = True
            # Ο master_key που έχουμε στη μνήμη προέρχεται από το ΠΑΛΙΟ
            # salt -- δεν είναι πια σωστός. Αποσύνδεση, ώστε το επόμενο
            # login να τον ξαναϋπολογίσει με το νέο salt.
            sid = session.pop("sid", None)
            if sid:
                SESSIONS.pop(sid, None)

    imported = 0
    skipped = 0
    conn = get_connection()
    try:
        database.create_table(conn)
        for i, raw in enumerate(raw_entries):
            problem = _validate_import_row(raw)
            if problem:
                skipped += 1
                errors.append(f"Εγγραφή #{i + 1} παραλείφθηκε: {problem}")
                continue
            database.insert_user(
                conn, raw.get("name", ""), raw["pattern"], raw["salt"], raw["ciphertext"]
            )
            imported += 1
    finally:
        conn.close()

    return render_template(
        "import.html",
        db_path=DB_PATH,
        result={"imported": imported, "skipped": skipped, "master_restored": master_restored},
        errors=errors or None,
    )


if __name__ == "__main__":
    print(f"Χρησιμοποιείται η βάση: {Path(DB_PATH).resolve()}")
    app.run(host="127.0.0.1", port=5000, debug=False)
