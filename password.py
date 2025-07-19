# Password Manager
# Description: A secure, command-line based password manager written in Python.
# It uses strong encryption to store and manage user passwords.

# Required library: cryptography
# Install it using pip: pip install cryptography

import os
import base64
from getpass import getpass  # To hide password input
import string
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration ---
KEY_FILE = "secret.key"
DB_FILE = "passwords.db"
SALT_SIZE = 16 # 16 bytes is a good standard for salt

# --- Core Functions ---

def generate_key_from_master_password(master_password, salt):
    """Derives a key from the master password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, # Recommended number of iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def setup():
    """Sets up the necessary files on the first run."""
    print("--- First Time Setup ---")
    
    # Get master password
    while True:
        master_password = getpass("Please create a master password: ")
        confirm_password = getpass("Confirm master password: ")
        if master_password == confirm_password:
            if master_password:
                break
            else:
                print("Master password cannot be empty.")
        else:
            print("Passwords do not match. Please try again.")

    # Generate a salt and derive the key
    salt = os.urandom(SALT_SIZE)
    key = generate_key_from_master_password(master_password, salt)
    
    # Save the salt and key to the key file
    with open(KEY_FILE, "wb") as f:
        f.write(salt)
        f.write(key)
    
    # Create the empty database file
    with open(DB_FILE, "w") as f:
        pass # Just create the file

    print("\n✅ Setup complete! Your secure key has been generated.")
    print(f"⚠️ IMPORTANT: Do not delete '{KEY_FILE}' or '{DB_FILE}'.")
    return key

def load_key(master_password):
    """Loads the encryption key using the master password."""
    try:
        with open(KEY_FILE, "rb") as f:
            salt = f.read(SALT_SIZE)
            stored_key = f.read()
        
        # Derive key from provided master password and compare
        derived_key = generate_key_from_master_password(master_password, salt)

        if derived_key == stored_key:
            return derived_key
        else:
            return None # Invalid master password
    except FileNotFoundError:
        return None # Key file not found

def encrypt_message(message, key):
    """Encrypts a message."""
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message.decode()

def decrypt_message(encrypted_message, key):
    """Decrypts an encrypted message."""
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message.encode())
        return decrypted_message.decode()
    except Exception:
        return None # Decryption failed

# --- Password Management Functions ---

def add_password(key):
    """Adds a new service, username, and password to the database."""
    service = input("Enter the service name (e.g., Google, Facebook): ").strip()
    username = input(f"Enter the username/email for {service}: ").strip()
    
    # Option to generate or manually enter password
    choice = input("Generate a strong password? (y/n): ").lower()
    if choice == 'y':
        length_str = input("Enter password length (default 16): ")
        try:
            length = int(length_str) if length_str else 16
            password = generate_strong_password(length)
            print(f"Generated Password: {password}")
        except ValueError:
            print("Invalid length. Using default 16.")
            password = generate_strong_password()
            print(f"Generated Password: {password}")
    else:
        password = getpass("Enter the password: ")

    # Encrypt all parts
    encrypted_service = encrypt_message(service, key)
    encrypted_username = encrypt_message(username, key)
    encrypted_password = encrypt_message(password, key)

    # Append to the database file
    with open(DB_FILE, "a") as f:
        f.write(f"{encrypted_service}|{encrypted_username}|{encrypted_password}\n")
    
    print(f"\n✅ Password for '{service}' added successfully!")

def get_password(key):
    """Retrieves and decrypts a password for a given service."""
    service_to_find = input("Enter the service name to retrieve: ").strip().lower()
    
    try:
        with open(DB_FILE, "r") as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 3:
                    encrypted_service, encrypted_username, encrypted_password = parts
                    decrypted_service = decrypt_message(encrypted_service, key)

                    if decrypted_service and decrypted_service.lower() == service_to_find:
                        decrypted_username = decrypt_message(encrypted_username, key)
                        decrypted_password = decrypt_message(encrypted_password, key)
                        print("\n--- Password Found ---")
                        print(f"Service: {decrypted_service}")
                        print(f"Username: {decrypted_username}")
                        print(f"Password: {decrypted_password}")
                        print("----------------------")
                        return
        print(f"\n❌ No password found for service '{service_to_find}'.")
    except FileNotFoundError:
        print(f"Database file '{DB_FILE}' not found.")

def list_services(key):
    """Lists all services stored in the database."""
    print("\n--- Stored Services ---")
    try:
        with open(DB_FILE, "r") as f:
            lines = f.readlines()
            if not lines:
                print("No services stored yet.")
                return

            for i, line in enumerate(lines):
                parts = line.strip().split('|')
                if len(parts) > 0:
                    decrypted_service = decrypt_message(parts[0], key)
                    if decrypted_service:
                        print(f"{i+1}. {decrypted_service}")
    except FileNotFoundError:
        print(f"Database file '{DB_FILE}' not found.")
    print("-----------------------")

def generate_strong_password(length=16):
    """Generates a cryptographically strong password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# --- Main Application Logic ---

def main():
    """Main function to run the password manager."""
    # Check if setup has been run
    if not os.path.exists(KEY_FILE):
        key = setup()
    else:
        master_password = getpass("Enter your master password: ")
        key = load_key(master_password)
        if not key:
            print("❌ Invalid master password. Exiting.")
            return
        print("\n✅ Access granted.")

    # Main loop
    while True:
        print("\n--- Password Manager Menu ---")
        print("1. Add a new password")
        print("2. Get a password")
        print("3. List all services")
        print("4. Generate a strong password")
        print("5. Quit")
        
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            add_password(key)
        elif choice == '2':
            get_password(key)
        elif choice == '3':
            list_services(key)
        elif choice == '4':
            length_str = input("Enter password length (default 16): ")
            try:
                length = int(length_str) if length_str else 16
                pw = generate_strong_password(length)
                print(f"\nGenerated Strong Password: {pw}")
            except ValueError:
                print("Invalid length. Using default 16.")
                pw = generate_strong_password()
                print(f"\nGenerated Strong Password: {pw}")
        elif choice == '5':
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()