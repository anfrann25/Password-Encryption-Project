# 🔐 Password Manager (Python)

Ένας ασφαλής **Password Manager** γραμμένος σε **Python 3**, διαθέσιμος σε **δύο εναλλακτικές διεπαφές** που μοιράζονται ακριβώς την ίδια λογική κρυπτογράφησης:

| Επιλογή | Πού βρίσκεται | Πώς τρέχει |
|---|---|---|
| **Command Line (CLI)** | `src/commandLine/` | Διαδραστικό μενού στο τερματικό |
| **Web App** | `src/webapp/` | Τοπικός web server (Flask) + browser στο `localhost` |

Το project ξεκίνησε ως port ενός πρωτότυπου C++ project και έχει εξελιχθεί σε κάτι πιο ολοκληρωμένο: πραγματική προστασία με **Master Password**, ισχυρή παραγωγή κλειδιών και τοπική αποθήκευση σε **SQLite**.

---

## Τι κάνει το project

1. **Master Password.** Την πρώτη φορά που ανοίγεις μια βάση, ορίζεις ένα master password. Από αυτό παράγεται ένα ισχυρό κλειδί με **PBKDF2-HMAC-SHA256** (200.000 επαναλήψεις) πάνω σε τυχαίο salt. Το ίδιο το password **δεν αποθηκεύεται ποτέ** — μόνο ένας «verifier» (keyed hash) που επιβεβαιώνει ότι ξαναδίνεις το σωστό password στην επόμενη είσοδο.
2. **Υβριδική κρυπτογράφηση (Algorithm A/B chain).** Κάθε κωδικός που αποθηκεύεις περνάει από μια αλυσίδα βημάτων: κάθε βήμα είναι είτε **Algorithm A** (προσθετική μετατόπιση, Caesar-style) είτε **Algorithm B** (XOR), ανάλογα με ένα 6-bit binary pattern. Το πραγματικό μυστικό κλειδί κάθε βήματος προέρχεται από το master key + ένα μοναδικό, τυχαίο **salt ανά εγγραφή** — έτσι το ίδιο password δύο φορές δίνει διαφορετικό ciphertext.
3. **Έλεγχος ισχύος κωδικού.** Κάθε νέος κωδικός πρέπει να έχει τουλάχιστον 8 χαρακτήρες, κεφαλαίο, πεζό, αριθμό και ειδικό χαρακτήρα.
4. **SQLite persistence.** Όλες οι εγγραφές (όνομα, pattern, salt, ciphertext) και τα στοιχεία επαλήθευσης του master password ζουν σε ένα αρχείο `.db`, το οποίο είναι φορητό — μπορείς να το πάρεις σε άλλο PC και να συνεχίσεις εκεί, αρκεί να θυμάσαι το master password.
5. **CLI και Web App είναι δύο "views" πάνω στην ίδια βάση** — και τα δύο χρησιμοποιούν αυτόματα τα ίδια modules κρυπτογράφησης (`crypto.py`, `master.py`, `database.py`, `models.py`, `functions.py`), οπότε μια βάση που φτιάχτηκε από το ένα διαβάζεται κανονικά από το άλλο.

Παραμένει ένα **εκπαιδευτικό** project, όχι audited crypto library για πραγματική χρήση σε ευαίσθητα δεδομένα.

---

## Πώς λειτουργεί η κρυπτογράφηση (βήμα-βήμα)

Αυτό είναι το πιο "ιδιαίτερο" κομμάτι του project, γι' αυτό αξίζει ξεχωριστή ανάλυση. Η διαδικασία έχει δύο ανεξάρτητα κομμάτια που συνδυάζονται: το **pattern** (ποια αλυσίδα αλγορίθμων θα τρέξει) και το **key** (με ποια μυστικά νούμερα θα τρέξει).

### 1. Παραγωγή του "pattern" (το binary κομμάτι)

Το pattern είναι ένα **6-bit binary string** (π.χ. `010010`) που λειτουργεί σαν "συνταγή": κάθε bit λέει ποιο από τα δύο αλγόριθμα θα τρέξει σε αυτό το βήμα.

Η παραγωγή του γίνεται σε δύο "γύρους" δεκαδικό → binary (κληρονομιά από το αρχικό C++ project):

```text
Βήμα 1: Διάλεξε (ή δώσε στο CLI) έναν αριθμό 1-50           π.χ. number = 13
Βήμα 2: Μετάτρεψέ τον σε binary (6-bit)                     13  -> "001101"
Βήμα 3: Πάρε έναν τυχαίο αριθμό στο [0, number] και πρόσθεσέ
        τον στο number. Αν ξεπεράσει το 50, αφαίρεσε ξανά
        το number (clamp).                                  π.χ. -> random_value = 18
Βήμα 4: Μετάτρεψε ΚΑΙ αυτόν σε binary (6-bit)                18  -> "010010"  <- αυτό είναι το τελικό pattern
```

Στο CLI ο αριθμός στο Βήμα 1 τον δίνει ο χρήστης χειροκίνητα· στο Web App παράγεται αυτόματα (τυχαία), γιατί δεν είναι πραγματικό μυστικό — απλώς επιλέγει *ποια* αλυσίδα αλγορίθμων θα εφαρμοστεί, όχι *με τι κλειδί*.

> 🔑 **Σημαντικό:** το pattern αποθηκεύεται σε καθαρό κείμενο δίπλα στο ciphertext (στήλη `Password` του πίνακα `Records`). Με μόνο 6 bits υπάρχουν μόλις 64 πιθανές τιμές — δεν προσφέρει καμία μυστικότητα από μόνο του. Η πραγματική ασφάλεια έρχεται αποκλειστικά από το **key** παρακάτω.

### 2. Παραγωγή του πραγματικού κλειδιού (key)

```text
master password  --PBKDF2-HMAC-SHA256 (200.000 iters, salt)-->  master_key (32 bytes)
master_key + per-entry salt  --HMAC-SHA256-->  entry_key (32 bytes)  (διαφορετικό για ΚΑΘΕ εγγραφή)
```

Το `entry_key` είναι αυτό που πραγματικά κρατά μυστικά τα δεδομένα — όχι το pattern.

### 3. Η αλυσίδα Algorithm A / Algorithm B

Ο κωδικός μετατρέπεται σε bytes (UTF-8) και περνάει, bit-προς-bit από το pattern, μέσα από μια αλυσίδα βημάτων, **από αριστερά προς τα δεξιά**:

- bit `'1'` → **Algorithm A** — προσθετική μετατόπιση όλων των bytes: `(byte + shift) mod 256`
- bit `'0'` → **Algorithm B** — XOR όλων των bytes με ένα κλειδί: `byte XOR xor_key`

Το `shift` και το `xor_key` σε κάθε βήμα **δεν είναι σταθερά** — υπολογίζονται από το `entry_key` και τη θέση του βήματος στην αλυσίδα, ώστε κάθε βήμα να χρησιμοποιεί διαφορετικό "υπο-κλειδί" ακόμα κι αν επαναλαμβάνεται το ίδιο bit.

Στην αποκρυπτογράφηση γίνεται ακριβώς το αντίστροφο: τα ίδια βήματα εφαρμόζονται **με αντίστροφη σειρά**, το καθένα με την αντίστροφή του πράξη (αφαίρεση αντί για πρόσθεση· το XOR είναι ήδη δικό του αντίστροφο).

### 4. Πλήρες παράδειγμα (πραγματική έξοδος του κώδικα)

```text
number = 13            -> binary "001101"
random_value = 18       -> pattern = "010010"   (6 βήματα: B, A, A, B, A, B)

master password -> master_key (PBKDF2, 200.000 iters)
master_key + entry salt -> entry_key = c529a320...  (32 bytes)

plaintext:  "Sup3r$ecret"
ciphertext (hex): e2403d824311d0d243d041

Πριν αποθηκευτεί, μπαίνει το σύμβολο "!" ακριβώς στη μέση του hex string:
stored ciphertext: e2403d82431!1d0d243d041
```

Χωρίς το σωστό `entry_key` (άρα χωρίς το σωστό master password), το να ξέρεις το pattern και το ciphertext δεν αρκεί για να ανακτήσεις το αρχικό password.

### Γιατί το pattern από μόνο του δεν αρκεί

Επειδή το `shift`/`xor_key` κάθε βήματος προέρχεται από το `entry_key` (32 τυχαία bytes ανά εγγραφή, εξαρτημένα από το master password), όχι από το pattern. Ένας επιτιθέμενος που βλέπει τη βάση βλέπει pattern + ciphertext + salt, αλλά όχι το master password ούτε το `entry_key` — και χωρίς αυτό δεν μπορεί να αντιστρέψει τα βήματα.

---

## Δομή του Project

```text
Password-Encryption-Project/
│
├── README.md                     # Αυτό το αρχείο
│
└── src/
    ├── commandLine/               # Επιλογή 1: CLI εφαρμογή
    │   ├── main.py                 # Entry point (python3 main.py)
    │   ├── password_manager/
    │   │   ├── cli.py               # Διαδραστικό μενού
    │   │   ├── crypto.py            # Algorithm A/B chain (encrypt/decrypt)
    │   │   ├── master.py            # Master password -> κλειδί (PBKDF2 + verifier)
    │   │   ├── database.py          # SQLite layer
    │   │   ├── functions.py         # Validation, pattern generation κτλ.
    │   │   └── models.py            # Password entry (encrypt/decrypt object)
    │   └── tests/                  # Unit tests (unittest)
    │
    └── webapp/                    # Επιλογή 2: Web εφαρμογή (Flask)
        ├── app.py                  # Entry point (python3 app.py)
        ├── requirements.txt         # Εξαρτήσεις (Flask)
        ├── templates/               # login.html, entries.html, base.html
        └── password_manager/        # Ίδια λογική με το commandLine (crypto, master, database...)
```

---

## Επιλογή 1: Command Line (CLI)

Δεν χρειάζεται καμία εξωτερική βιβλιοθήκη — μόνο η standard library της Python 3.

### Εκτέλεση

```bash
cd src/commandLine

# χρησιμοποιεί ./database.db (δημιουργείται αν δεν υπάρχει)
python3 main.py

# ή δώσε συγκεκριμένο path για τη βάση
python3 main.py path/to/my/database.db
```

Την πρώτη φορά θα σου ζητηθεί να ορίσεις master password. Τις επόμενες φορές θα σου ζητηθεί να το ξαναδώσεις (μέχρι 3 προσπάθειες).

### Μενού

```text
1. Insert New Password   -> προσθήκη νέας εγγραφής (όνομα + κωδικός)
2. Remove Password       -> διαγραφή εγγραφής με βάση τον αριθμό της στη λίστα
3. Show List (encrypted) -> εμφάνιση όλων των εγγραφών (κρυπτογραφημένες)
4. Decrypt an Entry      -> αποκρυπτογράφηση συγκεκριμένης εγγραφής
5. Exit                  -> αποθήκευση και έξοδος
```

### Tests

```bash
cd src/commandLine
python3 -m unittest discover -s tests
```

---

## Επιλογή 2: Web App

Ίδια λογική με το CLI, αλλά με φόρμες σε browser αντί για prompts στο τερματικό. Χρειάζεται το `Flask`.

### Εγκατάσταση (μία φορά)

```bash
cd src/webapp
pip install -r requirements.txt
```

### Εκτέλεση

```bash
# χρησιμοποιεί ./database.db (default)
python3 app.py

# ή δώσε path στη δικιά σου βάση
python3 app.py path/to/my/database.db
```

Μετά άνοιξε στον browser: **http://127.0.0.1:5000**

- Στην πρώτη είσοδο θα δεις φόρμα ορισμού master password· στις επόμενες, φόρμα login.
- Από τη λίστα εγγραφών μπορείς να προσθέσεις νέα ("Insert"), να αποκρυπτογραφήσεις μία εγγραφή ("Decrypt") ή να τη διαγράψεις ("Delete").

### Σημαντικό για την ασφάλεια

- Ο master key κρατιέται **μόνο στη μνήμη του server process** (in-memory session dict) — ποτέ σε cookie ή στο δίσκο. Κλείνοντας τον server (`Ctrl+C`) χάνεται, οπότε στην επόμενη εκκίνηση θα χρειαστεί ξανά login.
- Ο server ακούει μόνο σε `127.0.0.1` (localhost) — δεν είναι προσβάσιμος από άλλα μηχανήματα στο δίκτυο.

### Το "φορητό .db"

Το `.db` αρχείο είναι μια απλή SQLite βάση που περιέχει μόνο κρυπτογραφημένα δεδομένα + το PBKDF2 salt/verifier — ποτέ το master password σε καθαρό κείμενο. Μπορείς να το μεταφέρεις (USB, cloud κ.λπ.) σε άλλο PC με το ίδιο repo και να το ανοίξεις με:

```bash
python3 app.py path/στο/database.db
```

...δίνοντας τον ίδιο master password, θα δεις τις ίδιες εγγραφές.

---

## Γνωστό, προϋπάρχον θέμα στα tests

Τα 3 tests στο `src/commandLine/tests/test_database.py` αποτυχαίνουν ήδη, γιατί καλούν `insert_user()` με παλιά υπογραφή (πριν προστεθεί η στήλη `Name`). Άσχετο με τη λειτουργία CLI/Web — χρειάζεται μικρό update στα tests όποτε βολεύει.

## Ασφάλεια — σύνοψη

- Master password → PBKDF2-HMAC-SHA256, 200.000 επαναλήψεις, τυχαίο salt.
- Verifier αποθηκεύεται (όχι το password), σύγκριση με constant-time comparison (`hmac.compare_digest`).
- Κάθε εγγραφή έχει δικό της τυχαίο salt → ίδιο password, διαφορετικό ciphertext κάθε φορά.
- Δεν είναι audited crypto library — εκπαιδευτικό project.