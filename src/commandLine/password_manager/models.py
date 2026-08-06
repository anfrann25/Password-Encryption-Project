from __future__ import annotations

from dataclasses import dataclass

from . import crypto, master

# Το σύμβολο που θα προστίθεται στο τελικό encrypted string
SYMBOL_TO_INSERT = "!"


@dataclass
class Password:
    key: str
    salt: str
    ciphertext: str
    name: str = ""

    @classmethod
    def encrypt(
        cls, plaintext_password: str, pattern: str, master_key: bytes, name: str = ""
    ) -> "Password":
        entry_salt = master.generate_salt()
        entry_key = master.derive_entry_key(master_key, entry_salt)
        
        cipher_bytes = crypto.encrypt(plaintext_password, pattern, entry_key)
        raw_hex = cipher_bytes.hex()
        
        # 🟢 Εισαγωγή του συμβόλου ακριβώς στη μέση του encrypted string
        mid_index = len(raw_hex) // 2
        formatted_ciphertext = raw_hex[:mid_index] + SYMBOL_TO_INSERT + raw_hex[mid_index:]

        return cls(key=pattern, salt=entry_salt.hex(), ciphertext=formatted_ciphertext, name=name)

    def decrypt(self, master_key: bytes) -> str:
        entry_salt = bytes.fromhex(self.salt)
        entry_key = master.derive_entry_key(master_key, entry_salt)
        
        # 🟢 Αφαίρεση του συμβόλου πριν γίνει η αποκρυπτογράφηση
        clean_hex = self.ciphertext.replace(SYMBOL_TO_INSERT, "")
        
        return crypto.decrypt(bytes.fromhex(clean_hex), self.key, entry_key)

    def display(self) -> None:
        label = self.name if self.name else "(unnamed)"
        print(f"[{label}] Key: {self.key}, Salt: {self.salt}, Encrypted: {self.ciphertext}")
