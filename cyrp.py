import os
import sys
import time
import getpass
import platform
import multiprocessing as mp
from typing import List, Optional
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
import psutil  # Requires `pip install psutil`
import tempfile
from tqdm import tqdm  # Requires `pip install tqdm`

# -----------------------
# CONFIG
# -----------------------
ENCRYPTED_EXTENSION = ".bya" 
DEFAULT_TIMEOUT = 100
ITERATIONS = 390000
LOG_FILE = "crypto_manager.log"
CHECK_INTERVAL = 5
CHUNK_SIZE = 64 * 1024
RETRY_DELAY = 1
MAX_RETRIES = 5

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
    print(f"System: {platform.system()} {platform.release()} | CPU Cores: {mp.cpu_count()}\n")

# -----------------------
# Crypto Manager Class
# -----------------------
class CryptoManager:
    def __init__(self, password: bytes, use_ssd: bool = False):
        self.password = password
        self.backend = default_backend()
        self.use_ssd = use_ssd

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def _retry_replace(self, src: str, dst: str) -> bool:
        for attempt in range(MAX_RETRIES):
            try:
                os.replace(src, dst)
                return True
            except PermissionError as e:
                logger.warning(f"Retry {attempt + 1}/{MAX_RETRIES} - File locked: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error(f"Failed to replace {src} -> {dst} after {MAX_RETRIES} attempts")
                    return False
        return False

    def encrypt_file(self, filepath: str) -> bool:
        try:
            logger.info(f"Encrypting: {filepath}")
            file_size = os.path.getsize(filepath)
            salt = os.urandom(16)
            iv = os.urandom(16)
            key = self._derive_key(salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()

            encrypted_filepath = filepath + ENCRYPTED_EXTENSION
            temp_path = None
            with tqdm(total=file_size, desc=f"Encrypting {os.path.basename(filepath)}", unit="B", unit_scale=True) as pbar:
                if self.use_ssd:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_path = temp_file.name
                        with open(filepath, 'rb') as f_in, open(temp_path, 'wb') as f_out:
                            f_out.write(salt + iv)
                            while chunk := f_in.read(CHUNK_SIZE):
                                padded_chunk = padder.update(chunk)
                                encrypted_chunk = encryptor.update(padded_chunk)
                                f_out.write(encrypted_chunk)
                                pbar.update(len(chunk))
                            final_padded = padder.finalize()
                            f_out.write(encryptor.update(final_padded) + encryptor.finalize())
                    if not self._retry_replace(temp_path, encrypted_filepath):
                        raise OSError(f"Could not replace {temp_path} with {encrypted_filepath}")
                else:
                    with open(filepath, 'rb') as f_in, open(encrypted_filepath, 'wb') as f_out:
                        f_out.write(salt + iv)
                        while chunk := f_in.read(CHUNK_SIZE):
                            padded_chunk = padder.update(chunk)
                            encrypted_chunk = encryptor.update(padded_chunk)
                            f_out.write(encrypted_chunk)
                            pbar.update(len(chunk))
                        final_padded = padder.finalize()
                        f_out.write(encryptor.update(final_padded) + encryptor.finalize())

            os.remove(filepath)
            logger.info(f"Successfully encrypted: {filepath} -> {encrypted_filepath}")
            return True
        except Exception as e:
            logger.error(f"Encryption failed for {filepath}: {e}")
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    logger.info(f"Cleaned up temporary file: {temp_path}")
                except OSError:
                    logger.error(f"Failed to clean up temporary file: {temp_path}")
            return False

    def decrypt_file(self, filepath: str) -> Optional[str]:
        try:
            if not filepath.endswith(ENCRYPTED_EXTENSION):
                logger.warning(f"Not an encrypted file: {filepath}")
                return None

            logger.info(f"Decrypting: {filepath}")
            file_size = os.path.getsize(filepath) - 32
            with open(filepath, 'rb') as f_in:
                salt = f_in.read(16)
                iv = f_in.read(16)

            key = self._derive_key(salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            original_filepath = filepath[:-len(ENCRYPTED_EXTENSION)]
            temp_path = None
            with tqdm(total=file_size, desc=f"Decrypting {os.path.basename(filepath)}", unit="B", unit_scale=True) as pbar:
                if self.use_ssd:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_path = temp_file.name
                        with open(filepath, 'rb') as f_in, open(temp_path, 'wb') as f_out:
                            f_in.seek(32)
                            while chunk := f_in.read(CHUNK_SIZE):
                                decrypted_chunk = decryptor.update(chunk)
                                unpadded_chunk = unpadder.update(decrypted_chunk)
                                f_out.write(unpadded_chunk)
                                pbar.update(len(chunk))
                            final_decrypted = decryptor.finalize()
                            f_out.write(unpadder.update(final_decrypted) + unpadder.finalize())
                    if not self._retry_replace(temp_path, original_filepath):
                        raise OSError(f"Could not replace {temp_path} with {original_filepath}")
                else:
                    with open(filepath, 'rb') as f_in, open(original_filepath, 'wb') as f_out:
                        f_in.seek(32)
                        while chunk := f_in.read(CHUNK_SIZE):
                            decrypted_chunk = decryptor.update(chunk)
                            unpadded_chunk = unpadder.update(decrypted_chunk)
                            f_out.write(unpadded_chunk)
                            pbar.update(len(chunk))
                        final_decrypted = decryptor.finalize()
                        f_out.write(unpadder.update(final_decrypted) + unpadder.finalize())

            os.remove(filepath)
            logger.info(f"Successfully decrypted: {filepath} -> {original_filepath}")
            return original_filepath  # Return the decrypted file path
        except Exception as e:
            logger.error(f"Decryption failed for {filepath}: {e}")
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    logger.info(f"Cleaned up temporary file: {temp_path}")
                except OSError:
                    logger.error(f"Failed to clean up temporary file: {temp_path}")
            return None

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

def process_file(args: tuple) -> tuple[bool, Optional[str]]:
    filepath, password, action, use_ssd = args
    crypto = CryptoManager(password, use_ssd)
    if action == 'encrypt':
        success = crypto.encrypt_file(filepath)
        return success, None
    else:  # decrypt
        decrypted_path = crypto.decrypt_file(filepath)
        return decrypted_path is not None, decrypted_path

def process_files_parallel(files: List[str], password: bytes, action: str, use_full_cpu: bool, use_ssd: bool) -> tuple[int, List[str]]:
    if not files:
        return 0, []
    processes = mp.cpu_count() if use_full_cpu else 1
    with mp.Pool(processes=processes) as pool:
        results = pool.map(process_file, [(f, password, action, use_ssd) for f in files])
    success_count = sum(1 for success, _ in results if success)
    decrypted_files = [path for success, path in results if success and path is not None]
    return success_count, decrypted_files

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
def secure_access(password: bytes, use_full_cpu: bool, use_ssd: bool):
    target_paths = get_target_paths()

    if not target_paths:
        logger.error("No valid paths provided. Exiting.")
        print("[ERROR] No valid paths provided!")
        return

    try:
        # Initial encryption phase
        logger.info("Starting initial encryption process")
        print("\n[+] Encrypting unencrypted files...")
        initial_encrypt_files = collect_files(target_paths, 'encrypt')
        total_initial_encrypted, _ = process_files_parallel(initial_encrypt_files, password, 'encrypt', use_full_cpu, use_ssd)
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
        total_decrypted, decrypted_file_paths = process_files_parallel(decrypt_files, password, 'decrypt', use_full_cpu, use_ssd)
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
        encrypt_files = [f for f in decrypted_file_paths if os.path.exists(f)]  # Use decrypted files
        if not encrypt_files:
            print("[WARNING] No files found to re-encrypt!")
            logger.warning("No files found to re-encrypt")
            return

        total_encrypted = 0
        while encrypt_files:
            still_in_use = []
            encrypt_batch = []
            for filepath in encrypt_files:
                if not os.path.exists(filepath):
                    logger.warning(f"File no longer exists: {filepath}")
                    continue
                if is_file_in_use(filepath):
                    logger.warning(f"File in use: {filepath}")
                    print(f"[WARNING] File still in use: {filepath}")
                    still_in_use.append(filepath)
                else:
                    encrypt_batch.append(filepath)

            if encrypt_batch:
                encrypted_count, _ = process_files_parallel(encrypt_batch, password, 'encrypt', use_full_cpu, use_ssd)
                total_encrypted += encrypted_count
                print(f"[+] Re-encrypted {encrypted_count} files in this batch")

            if still_in_use:
                encrypt_files = still_in_use
                print(f"[INFO] Waiting {CHECK_INTERVAL} seconds for {len(still_in_use)} files to be released...")
                logger.info(f"Waiting {CHECK_INTERVAL} seconds for {len(still_in_use)} files in use")
                time.sleep(CHECK_INTERVAL)
            else:
                break

        print(f"[+] Re-encrypted {total_encrypted} files total. All files are now secure.")
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

def get_usage_preference(prompt: str) -> bool:
    response = input(prompt).strip().lower()
    return response == 'full'

# -----------------------
# Entry Point
# -----------------------
if __name__ == "__main__":
    display_intro()
    try:
        import psutil
        import tqdm
    except ImportError as e:
        print(f"[ERROR] Missing required module: {e}. Install with 'pip install {e.name}'")
        sys.exit(1)

    use_full_cpu = get_usage_preference(
        "Use full CPU power? (full/normal, press Enter for normal): "
    )
    use_full_ram = get_usage_preference(
        "Use full RAM? (full/normal, press Enter for normal, 'normal' uses SSD): "
    )
    use_ssd = not use_full_ram

    print(f"\n[INFO] Running with: CPU={'Full' if use_full_cpu else 'Normal'}, "
          f"Storage={'RAM' if use_full_ram else 'SSD'}")

    password = get_verified_password()
    if password is None:
        sys.exit(1)
    
    secure_access(password, use_full_cpu, use_ssd)
    print("\n[+] Process completed. Check crypto_manager.log for details.")