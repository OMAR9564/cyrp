import os
import sys
import time
import getpass
import platform
from typing import List, Optional
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
import psutil  # Requires `pip install psutil`

# -----------------------
# CONFIG
# -----------------------
ENCRYPTED_EXTENSION = ".bya"
DEFAULT_TIMEOUT = 100
ITERATIONS = 390000
LOG_FILE = "crypto_manager.log"
CHECK_INTERVAL = 5

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# -----------------------
# ASCII Art Display
# -----------------------
def display_intro():
    intro = [
        "\033[32m ▄▄▄▄ ▓██   ██▓ ▄▄▄      \033[0m",
        "▓█████▄▒██  ██▒▒████▄    ",
        "▒██▒ ▄██▒██ ██░▒██  ▀█▄  ",
        "▒██░█▀  ░ ▐██▓░░██▄▄▄▄██ ",
        "░▓█  ▀█▓░ ██▒▓░ ▓█   ▓██▒",
        "░▒▓███▀▒ ██▒▒▒  ▒▒   ▓▒█░",
        "▒░▒   ░▓██ ░▒░   ▒   ▒▒ ░",
        " ░    ░▒ ▒ ░░    ░   ▒   ",
        " ░     ░ ░           ░  ░",
        "      ░░ ░               "
    ]
    for line in intro:
        print(line)
        time.sleep(0.1)
    print("\nCryptoManager v1.0 - Secure File Encryption Tool")
    print(f"System: {platform.system()} {platform.release()}\n")

# -----------------------
# Crypto Manager Class
# -----------------------
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
            logger.info(f"Attempting to encrypt: {filepath}")
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
            
            os.remove(filepath)
            logger.info(f"Successfully encrypted: {filepath} -> {encrypted_filepath}")
            return True
        except Exception as e:
            logger.error(f"Encryption failed for {filepath}: {e}")
            return False

    def decrypt_file(self, filepath: str) -> bool:
        try:
            if not filepath.endswith(ENCRYPTED_EXTENSION):
                logger.warning(f"Not an encrypted file: {filepath}")
                return False

            logger.info(f"Attempting to decrypt: {filepath}")
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
            
            os.remove(filepath)
            logger.info(f"Successfully decrypted: {filepath} -> {original_filepath}")
            return True
        except Exception as e:
            logger.error(f"Decryption failed for {filepath}: {e}")
            return False

# -----------------------
# Helper Functions
# -----------------------
def is_file_in_use(filepath: str) -> bool:
    for proc in psutil.process_iter(['pid', 'open_files']):
        try:
            for file in proc.info['open_files'] or []:
                if file.path == filepath:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
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

def get_target_paths() -> List[str]:
    paths = []
    logger.info("Collecting target paths from user input")
    while True:
        path = input("Enter file or folder path to process (or 'q' to quit): ").strip()
        if path.lower() == 'q':
            break
        if not os.path.exists(path):
            logger.error(f"Path not found: {path}")
            print(f"[ERROR] Path not found: {path}")
            continue
        paths.append(path)
    logger.info(f"Collected paths: {paths}")
    return paths

def collect_files(target_paths: List[str], action: str) -> List[str]:
    files = []
    for path in target_paths:
        if os.path.isfile(path):
            if (action == 'decrypt' and path.endswith(ENCRYPTED_EXTENSION)) or \
               (action == 'encrypt' and not path.endswith(ENCRYPTED_EXTENSION)):
                files.append(path)
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for name in filenames:
                    file_path = os.path.join(root, name)
                    if (action == 'decrypt' and file_path.endswith(ENCRYPTED_EXTENSION)) or \
                       (action == 'encrypt' and not file_path.endswith(ENCRYPTED_EXTENSION)):
                        files.append(file_path)
    logger.info(f"Collected {action} files: {files}")
    return files

# -----------------------
# Main Application Logic
# -----------------------
def secure_access(password: bytes):
    crypto = CryptoManager(password)
    target_paths = get_target_paths()

    if not target_paths:
        logger.error("No valid paths provided. Exiting.")
        print("[ERROR] No valid paths provided!")
        return

    try:
        # Initial encryption phase (if files are unencrypted)
        logger.info("Starting initial encryption process for unencrypted files")
        print("\n[+] Encrypting unencrypted files...")
        initial_encrypt_files = collect_files(target_paths, 'encrypt')
        total_initial_encrypted = 0
        for filepath in initial_encrypt_files:
            if crypto.encrypt_file(filepath):
                total_initial_encrypted += 1

        if total_initial_encrypted > 0:
            print(f"[+] Initially encrypted {total_initial_encrypted} files")
            logger.info(f"Initially encrypted {total_initial_encrypted} files")
        else:
            print("[INFO] No unencrypted files found to encrypt initially")
            logger.info("No unencrypted files found to encrypt initially")

        # Decryption phase
        logger.info("Starting decryption process")
        print("\n[+] Decrypting files...")
        decrypt_files = collect_files(target_paths, 'decrypt')
        total_decrypted = 0
        for filepath in decrypt_files:
            total_decrypted += 1 if crypto.decrypt_file(filepath) else 0

        print(f"[+] Decrypted {total_decrypted} files")
        logger.info(f"Decrypted {total_decrypted} files")
        if total_decrypted == 0:
            print("[WARNING] No encrypted files found to decrypt!")
            logger.warning("No encrypted files found to decrypt")
            return

        # Timeout phase
        timeout_input = input(f"\nHow many seconds to keep files open? (Default {DEFAULT_TIMEOUT}s): ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else DEFAULT_TIMEOUT
        print(f"\n[+] Encrypting in {timeout} seconds...")
        logger.info(f"Waiting {timeout} seconds before re-encryption")
        time.sleep(timeout)

        # Re-encryption phase
        logger.info("Starting re-encryption process")
        print("\n[+] Time's up. Checking files for re-encryption...")
        encrypt_files = collect_files(target_paths, 'encrypt')
        if not encrypt_files:
            print("[WARNING] No files found to re-encrypt!")
            logger.warning("No files found to re-encrypt")
            return

        total_encrypted = 0
        while encrypt_files:
            still_in_use = []
            for filepath in encrypt_files:
                if not os.path.exists(filepath):
                    logger.warning(f"File no longer exists: {filepath}")
                    continue
                if is_file_in_use(filepath):
                    logger.warning(f"File in use: {filepath}")
                    print(f"[WARNING] File still in use: {filepath}")
                    still_in_use.append(filepath)
                else:
                    if crypto.encrypt_file(filepath):
                        total_encrypted += 1
                        print(f"[+] Re-encrypted: {filepath}")
                    else:
                        logger.error(f"Failed to re-encrypt: {filepath}")
                        print(f"[ERROR] Failed to re-encrypt: {filepath}")

            if still_in_use:
                encrypt_files = still_in_use
                print(f"[INFO] Waiting {CHECK_INTERVAL} seconds for {len(still_in_use)} files to be released...")
                logger.info(f"Waiting {CHECK_INTERVAL} seconds for {len(still_in_use)} files in use")
                time.sleep(CHECK_INTERVAL)
            else:
                break

        print(f"[+] Re-encrypted {total_encrypted} files. All files are now secure.")
        logger.info(f"Re-encrypted {total_encrypted} files")

    except KeyboardInterrupt:
        logger.warning("Process interrupted by user")
        print("\n[WARNING] Process interrupted by user!")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"[ERROR] An unexpected error occurred: {e}")

def get_verified_password() -> Optional[bytes]:
    for attempt in range(3):
        password1 = getpass.getpass("Enter encryption password (remember it!): ").encode()
        password2 = getpass.getpass("Confirm password: ").encode()
        
        if password1 == password2:
            return password1
        else:
            print(f"[ERROR] Passwords do not match! Attempt {attempt + 1}/3")
            logger.error(f"Password mismatch on attempt {attempt + 1}")
    
    print("[ERROR] Too many failed attempts. Exiting.")
    logger.error("Too many password mismatch attempts. Aborting.")
    return None

# -----------------------
# Entry Point
# -----------------------
if __name__ == "__main__":
    display_intro()
    try:
        import psutil
    except ImportError:
        print("[ERROR] 'psutil' module is required. Install it with 'pip install psutil'")
        sys.exit(1)
    
    password = get_verified_password()
    if password is None:
        sys.exit(1)
    
    secure_access(password)
    print("\n[+] Process completed. Check crypto_manager.log for details.")