# Password-Encryption-Project
## Password Encryption with Dynamic Algorithm Chain
Κρυπτογράφηση Κωδικών με Δυναμική Αλυσίδα Αλγορίθμων

Αυτό το project υλοποιεί ένα σύστημα κρυπτογράφησης κωδικών σε C++ που χρησιμοποιεί σειριακή εφαρμογή αλγορίθμων κρυπτογράφησης με βάση ένα δυναμικά παραγόμενο δυαδικό μοτίβο.

## Περιγραφή

Ο χρήστης εισάγει έναν κωδικό και έναν αριθμό από το 1 έως το 50. Το σύστημα μετατρέπει τον αριθμό αυτόν σε έναν δυαδικό αριθμό (π.χ. 101001), ο οποίος καθορίζει ποιον αλγόριθμο θα χρησιμοποιήσει για κάθε βήμα της κρυπτογράφησης.

* 1 → Χρήση Αλγορίθμου Α

* 0 → Χρήση Αλγορίθμου Β

Η κρυπτογράφηση εφαρμόζεται σειριακά, δημιουργώντας ένα μοναδικό αποτέλεσμα για κάθε συνδυασμό εισόδου.

Το αποτέλεσμα αποθηκεύεται σε βάση δεδομένων, μαζί με το αντίστοιχο δυαδικό μοτίβο, ώστε να μπορεί να γίνει αποκρυπτογράφηση μόνο από το ίδιο το σύστημα.

## Χαρακτηριστικά

* Κρυπτογράφηση με βάση δυαδική ακολουθία

* Υποστήριξη πολλαπλών αλγορίθμων (Α, Β)

* Αποθήκευση κρυπτογραφημένων δεδομένων σε SQLite

* Δυνατότητα αποκρυπτογράφησης μόνο με τον σωστό "αλγόριθμο μονοπατιού"

* Modular C++ κώδικας, εύκολος στην επέκταση

## Σημείωση Ασφαλείας

Το project είναι εκπαιδευτικού χαρακτήρα και δεν προτείνεται για χρήση σε παραγωγικά συστήματα. Δεν ακολουθεί πλήρως όλα τα πρότυπα ασφάλειας (π.χ. key management, HMAC validation κ.λπ.)

Password Encryption with Dynamic Algorithm Chain

This project implements a C++-based password encryption system using a serial chain of encryption algorithms based on a dynamically generated binary pattern.

Description

The user provides a password and a number between 1 and 50. This number is internally converted into a binary string (e.g., 101001), which determines which encryption algorithm is applied at each step.

1 → Use Algorithm A

0 → Use Algorithm B

The encryption is applied sequentially, creating a unique output for each input combination.

The final encrypted output is stored in a database (e.g., SQLite), along with the binary pattern, allowing decryption only through the original system.

Features

Binary-driven encryption sequence

Multiple algorithm support (A, B)

Encrypted data stored in SQLite database

Decryption possible only with the correct binary "algorithm path"

Modular, extendable C++ codebase

Security Note

This project is intended for educational purposes only and is not recommended for production use. It does not fully implement modern cryptographic best practices (e.g., key management, HMAC verification, etc.)