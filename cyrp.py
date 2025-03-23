import os
import sys
import time
import getpass
import platform
from typing import Optional
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# -----------------------
# CONFIG
# -----------------------
ENCRYPTED_EXTENSION = ".encrypted"
DEFAULT_TIMEOUT = 100
ITERATIONS = 390000

class CryptoManager:
    def __init__(self, password: bytes):
        self.password = password
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt_file(self, filepath: str) -> bool:
        try:
            print(f"[+] Şifreleniyor: {filepath}")
            with open(filepath, 'rb') as f:
                data = f.read()

            salt = os.urandom(16)
            iv = os.urandom(16)
            key = self._derive_key(salt)

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            encrypted_filepath = filepath + ENCRYPTED_EXTENSION
            with open(encrypted_filepath, 'wb') as f:
                f.write(salt + iv + encrypted_data)
            
            os.remove(filepath)  # Orijinal dosyayı sil
            return True
        except Exception as e:
            print(f"[HATA] Şifreleme başarısız {filepath}: {e}")
            return False

    def decrypt_file(self, filepath: str) -> bool:
        try:
            if not filepath.endswith(ENCRYPTED_EXTENSION):
                print(f"[UYARI] Şifreli dosya değil: {filepath}")
                return False

            print(f"[+] Çözülüyor: {filepath}")
            with open(filepath, 'rb') as f:
                file_data = f.read()

            salt = file_data[:16]
            iv = file_data[16:32]
            encrypted_data = file_data[32:]
            key = self._derive_key(salt)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_padded) + unpadder.finalize()

            original_filepath = filepath[:-len(ENCRYPTED_EXTENSION)]
            with open(original_filepath, 'wb') as f:
                f.write(data)
            
            os.remove(filepath)  # Şifreli dosyayı sil
            return True
        except Exception as e:
            print(f"[HATA] Çözme başarısız {filepath}: {e}")
            return False

def process_folder(folder: str, crypto: CryptoManager, action: str) -> int:
    success_count = 0
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            if action == 'encrypt' and not path.endswith(ENCRYPTED_EXTENSION):
                if crypto.encrypt_file(path):
                    success_count += 1
            elif action == 'decrypt' and path.endswith(ENCRYPTED_EXTENSION):
                if crypto.decrypt_file(path):
                    success_count += 1
    return success_count

def get_target_paths() -> list:
    paths = []
    while True:
        path = input("Şifrelenecek/çözülecek dosya veya klasör yolunu girin (Çıkmak için 'q'): ").strip()
        if path.lower() == 'q':
            break
        if not os.path.exists(path):
            print(f"[HATA] Yol bulunamadı: {path}")
            continue
        paths.append(path)
    return paths

def secure_access(password: bytes):
    crypto = CryptoManager(password)
    
    # Terminalden yolları al
    target_paths = get_target_paths()
    if not target_paths:
        print("[HATA] Hiçbir geçerli yol girilmedi!")
        return

    try:
        # Çözme işlemi
        print("\n[+] Dosyalar çözülüyor...")
        total_decrypted = 0
        for path in target_paths:
            if os.path.isfile(path):
                total_decrypted += 1 if crypto.decrypt_file(path) else 0
            elif os.path.isdir(path):
                total_decrypted += process_folder(path, crypto, 'decrypt')

        print(f"[+] Çözülen dosya sayısı: {total_decrypted}")
        if total_decrypted == 0:
            print("[UYARI] Çözülecek dosya bulunamadı!")

        # Zamanlayıcı
        timeout = input(f"\nKaç saniye açık kalsın? (Varsayılan {DEFAULT_TIMEOUT} sn): ").strip()
        timeout = int(timeout) if timeout.isdigit() else DEFAULT_TIMEOUT
        print(f"\n[+] {timeout} saniye sonra şifreleme başlayacak...")
        time.sleep(timeout)

        # Tekrar şifreleme
        print("\n[+] Süre doldu. Şifreleme başlatılıyor...")
        total_encrypted = 0
        for path in target_paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                total_encrypted += 1 if crypto.encrypt_file(path) else 0
            elif os.path.isdir(path):
                total_encrypted += process_folder(path, crypto, 'encrypt')

        print(f"[+] Şifrelenen dosya sayısı: {total_encrypted}")
        
    except KeyboardInterrupt:
        print("\n[UYARI] Kullanıcı tarafından durduruldu!")
    except Exception as e:
        print(f"[HATA] Genel hata: {e}")

if __name__ == "__main__":
    print(f"\n[***] Sistem: {platform.system()} {platform.release()}")
    password = getpass.getpass("Şifre belirle (unutma!): ").encode()
    secure_access(password)