# 🔐 Password Manager (Python Port)

Ένας ελαφρύς, ασφαλής και διαδραστικός **Password Manager** γραμμένος σε **Python 3**, βασισμένος σε διεπαφή γραμμής εντολών (CLI). 

Το project αποτελεί αναβαθμισμένη μεταφορά (port) ενός πρωτότυπου C++ project, εμπλουτισμένο με σύγχρονους αλγόριθμους κρυπτογράφησης, διαχείριση Master Password και τοπική αποθήκευση σε βάση δεδομένων SQLite.

---

## 🚀 Χαρακτηριστικά (Features)

* **Master Password Protection:** Ταυτοποίηση χρήστη κατά την εκκίνηση με παραγωγή κλειδιών μέσω **PBKDF2-HMAC-SHA256** (200.000 iterations) και HMAC verifier.
* **Υβριδική Κρυπτογράφηση (Algorithm A/B Chain):** Συνδυασμός αλγεβρικής μετατόπισης (Caesar shift) και XOR operations, οδηγοί από δυναμικά binary patterns και μοναδικό salt ανά εγγραφή.
* **Formated Ciphertext:** Αυτόματη εισαγωγή ειδικών συμβόλων στο κρυπτογραφημένο αλφαριθμητικό για χρήση ως ισχυροί κωδικοί πρόσβασης.
* **Πλήρης Έλεγχος Ισχύος Κωδικού:** Ενσωματωμένος μηχανισμός ελέγχου απαιτήσεων ασφαλείας (κεφαλαία, πεζά, αριθμοί, ειδικοί χαρακτήρες, ελάχιστο μήκος).
* **SQLite Persistence:** Τοπική αποθήκευση όλων των εγγραφών και των ρυθμίσεων ασφαλείας στο αρχείο `database.db`.

---

## 🛠️ Δομή του Project

```text
python_port/
│
├── main.py                   # Το σημείο εκκίνησης (Entry Point)
├── database.db               # Η τοπική βάση δεδομένων SQLite
├── README.md                 # Τεκμηρίωση του project
│
├── password_manager/         # Κύριο πακέτο εφαρμογής
│   ├── __init__.py
│   ├── cli.py                # Διαδραστικό μενού τερματικού (CLI flow)
│   ├── crypto.py             # Αλγόριθμοι κρυπτογράφησης & αποκρυπτογράφησης
│   ├── database.py           # Layer επικοινωνίας με τη SQLite
│   ├── functions.py          # Βοηθητικές συναρτήσεις & password validation
│   ├── master.py             # Παραγωγή Master Key & Salt management
│   └── models.py             # Data model (Password entry handling)
│
└── tests/                    # Unit tests
    ├── test_crypto.py
    ├── test_database.py
    ├── test_functions.py
    └── test_master.py
