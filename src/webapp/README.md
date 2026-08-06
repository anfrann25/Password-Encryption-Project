# Password Manager — Local Web UI

Οπτικοποίηση του υπάρχοντος CLI (`cli.py`) ως τοπικό web app. Δεν αλλάζει
καθόλου η κρυπτο-λογική: `crypto.py`, `master.py`, `database.py`,
`models.py` είναι αντίγραφα 1-προς-1 από το αρχικό project.

## Εγκατάσταση (μία φορά, ή σε κάθε νέο PC)

```bash
pip install -r requirements.txt
```

## Εκκίνηση

```bash
# χρησιμοποιεί ./database.db (default)
python3 app.py

# ή δώσε το path στο δικό σου .db
python3 app.py /path/to/my/database.db
```

Άνοιξε **http://127.0.0.1:5000** στον browser σου.

## Το "φορητό .db"

Το `.db` αρχείο είναι μια απλή SQLite βάση. Αν το πάρεις (usb, cloud
drive, κτλ.) σε άλλο PC που έχει αυτό το ίδιο repo:

```bash
python3 app.py /path/στο/database.db
```

...και θα δεις τις ίδιες εγγραφές, ζητώντας τον ίδιο master password.
Το `.db` περιέχει μόνο κρυπτογραφημένα δεδομένα + το PBKDF2 salt/verifier
— ποτέ τον master password σε καθαρό κείμενο.

## Ασφάλεια — τι να ξέρεις

- Ο master key ζει **μόνο στη μνήμη του server process**, ποτέ σε cookie
  ή στο δίσκο. Κλείνοντας το `python3 app.py` (Ctrl+C) χάνεται από τη
  μνήμη — θα χρειαστεί νέο login στην επόμενη εκκίνηση.
- Ο server ακούει μόνο σε `127.0.0.1` (localhost) — δεν είναι
  προσβάσιμος από άλλα μηχανήματα στο δίκτυο.
- Αυτό παραμένει ένα **εκπαιδευτικό project**, όχι audited crypto
  library (βλ. σχόλια στο `crypto.py`).

## Γνωστό, προϋπάρχον θέμα

Τα 3 tests σε `tests/test_database.py` αποτυχαίνουν ήδη στο αρχικό
repo (καλούν `insert_user()` με παλιά υπογραφή, πριν την προσθήκη της
στήλης `Name`). Άσχετο με το web UI — απλά χρειάζεται ένα μικρό update
στα tests όποτε βολεύει.
