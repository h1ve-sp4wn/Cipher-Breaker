import logging
import itertools
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor, as_completed

ENCRYPTED_TEXT = "wK7RVEuZx9YnVdjXLDq+jg=="  # Replace with the encrypted text (Base64 encoded)
KEYSPACE = b"abcdefghijklmnopqrstuvwxyz"  # Refined keyspace (lowercase only for practical brute force)
IV = b"1234567890123456"  # Replace with known IV if available

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decrypt_aes_cbc(encrypted_text, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        logging.error(f"Decryption failed with key {key.decode()}: {e}")
        return None

def decrypt_with_pbkdf2(password, salt):
    key = PBKDF2(password, salt, dkLen=16)  # AES requires a 16-byte key
    return decrypt_aes_cbc(ENCRYPTED_TEXT, key, IV)

def brute_force_decrypt():
    logging.info("[*] Starting brute-force attack on AES encryption...")
    start_time = time.time()
    attempt_count = 0
    
    for key in itertools.product(KEYSPACE, repeat=16):  # Reduce keyspace to lower case letters
        key = bytes(key)
        attempt_count += 1
        
        result = decrypt_aes_cbc(ENCRYPTED_TEXT, key, IV)
        if result:
            elapsed_time = time.time() - start_time
            logging.info(f"[+] Decryption successful! Key: {key.decode()} | Decrypted Text: {result}")
            logging.info(f"[+] Total Attempts: {attempt_count} | Time taken: {elapsed_time:.2f} seconds")
            return key.decode(), result
        
        if attempt_count % 100000 == 0:
            logging.info(f"[*] Attempt {attempt_count}...")
    
    logging.warning("[!] Brute-force failed to decrypt the text.")
    return None, None

def weak_password_aes_decrypt(password_list):
    logging.info("[*] Attempting weak password AES decryption...")
    start_time = time.time()
    attempt_count = 0
    
    for password in password_list:
        key = password.encode().ljust(16, b'\0')  # Pad the password to 16 bytes if shorter
        attempt_count += 1
        
        result = decrypt_aes_cbc(ENCRYPTED_TEXT, key, IV)
        if result:
            elapsed_time = time.time() - start_time
            logging.info(f"[+] Decryption successful with password: {password} | Decrypted Text: {result}")
            logging.info(f"[+] Total Attempts: {attempt_count} | Time taken: {elapsed_time:.2f} seconds")
            return password, result
        
        if attempt_count % 100 == 0:
            logging.info(f"[*] Attempt {attempt_count}...")
    
    logging.warning("[!] Weak password AES decryption failed.")
    return None, None

def crack_hash(md5_hash, wordlist_path):
    logging.info(f"[*] Cracking hash: {md5_hash} using wordlist: {wordlist_path}")
    try:
        with open(wordlist_path, "r") as wordlist:
            for word in wordlist:
                word = word.strip()
                hashed_word = hashlib.md5(word.encode()).hexdigest()
                if hashed_word == md5_hash:
                    logging.info(f"[+] Hash cracked! Password: {word}")
                    return word
    except Exception as e:
        logging.error(f"Error reading wordlist {wordlist_path}: {e}")
    
    logging.warning("[!] Failed to crack hash.")
    return None

def parallel_brute_force_decrypt():
    logging.info("[*] Starting parallel brute-force attack on AES encryption...")
    start_time = time.time()
    attempt_count = 0
    attempts = []
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        for key in itertools.product(KEYSPACE, repeat=16):
            key = bytes(key)
            attempt_count += 1
            future = executor.submit(decrypt_aes_cbc, ENCRYPTED_TEXT, key, IV)
            attempts.append(future)
        
        for future in as_completed(attempts):
            result = future.result()
            if result:
                elapsed_time = time.time() - start_time
                logging.info(f"[+] Decryption successful with key: {key.decode()} | Decrypted Text: {result}")
                logging.info(f"[+] Total Attempts: {attempt_count} | Time taken: {elapsed_time:.2f} seconds")
                return key.decode(), result
    
    logging.warning("[!] Parallel brute-force failed to decrypt the text.")
    return None, None

if __name__ == "__main__":
    logging.info("CIPHER BREAKER FRAMEWORK ACTIVATED")
    logging.info("[*] Decoding encrypted secrets...")
    
    key, decrypted_text = brute_force_decrypt()
    if key:
        logging.info(f"[+] Final Key: {key}")
        logging.info(f"[+] Decrypted Message: {decrypted_text}")
    
    password_list = ["password", "123456", "letmein", "qwerty"]  # Add more weak passwords
    weak_password, weak_decrypted_text = weak_password_aes_decrypt(password_list)
    if weak_password:
        logging.info(f"[+] Final Password: {weak_password}")
        logging.info(f"[+] Decrypted Message: {weak_decrypted_text}")
    
    example_hash = "5d41402abc4b2a76b9719d911017c592"  # Example MD5 hash ("hello")
    wordlist = "./wordlist.txt"  # Replace with the path to your wordlist
    crack_hash(example_hash, wordlist)
    
    key, decrypted_text = parallel_brute_force_decrypt()
    if key:
        logging.info(f"[+] Final Key from Parallel Brute Force: {key}")
        logging.info(f"[+] Decrypted Message from Parallel Brute Force: {decrypted_text}")