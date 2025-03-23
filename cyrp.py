import os
import sys
import time
import getpass
import platform
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# -----------------------
# CONFIG
# -----------------------
# Dosya veya klasörleri buraya ekle
TARGET_PATHS = [
    "gizli_dosya.txt",         # Tek dosya
    "gizli_klasor"             # Klasör (içindeki tüm dosyaları şifreler)
]

# Anahtar üretimi için
PASSWORD = getpass.getpass("Şifre belirle (unutma!): ").encode()

# -----------------------
# AES-256 Key Üretimi
# -----------------------
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password)

# -----------------------
# Dosya Şifreleme
# -----------------------
def encrypt_file(filepath, password):
    print(f"[+] Şifreleniyor: {filepath}")
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(filepath, 'wb') as f:
        f.write(salt + iv + encrypted_data)

# -----------------------
# Dosya Çözme
# -----------------------
def decrypt_file(filepath, password):
    print(f"[+] Decrypt ediliyor: {filepath}")
    with open(filepath, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(filepath, 'wb') as f:
        f.write(data)

# -----------------------
# Klasör İçeriğini İşle
# -----------------------
def process_folder(folder, password, action):
    for root, dirs, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            if action == 'encrypt':
                encrypt_file(path, password)
            elif action == 'decrypt':
                decrypt_file(path, password)

# -----------------------
# Ana İşleyiş
# -----------------------
def secure_access():
    try:
        print("\n[+] Dosyalar deşifre ediliyor...")
        for path in TARGET_PATHS:
            if os.path.isfile(path):
                decrypt_file(path, PASSWORD)
            elif os.path.isdir(path):
                process_folder(path, PASSWORD, 'decrypt')
            else:
                print(f"[!] Bulunamadı: {path}")

        # Kullanıcıdan süre al
        timeout = input("\nKaç saniye açık kalsın? (Varsayılan 100 sn): ").strip()
        if not timeout.isdigit():
            timeout = 100
        else:
            timeout = int(timeout)

        print(f"\n[+] {timeout} saniye sonra otomatik şifreleme başlayacak.")
        time.sleep(timeout)

        print("\n[+] Süre doldu. Tekrar şifreleniyor...")
        for path in TARGET_PATHS:
            if os.path.isfile(path):
                encrypt_file(path, PASSWORD)
            elif os.path.isdir(path):
                process_folder(path, PASSWORD, 'encrypt')
            else:
                print(f"[!] Bulunamadı: {path}")

        print("\n[+] Tüm dosyalar tekrar şifrelendi.")
    except Exception as e:
        print(f"[HATA]: {e}")

if __name__ == "__main__":
    print(f"\n[***] Sistem: {platform.system()} {platform.release()}")
    secure_access()
