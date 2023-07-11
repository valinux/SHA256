
import os
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class FileEncrypter:
    def __init__(self, filename):
        self._filename = filename

    def encrypt(self, password, salt_filename):
        if not os.path.exists(self._filename):
            raise ValueError("File does not exist")

        salt, key = self._generate_key(password)
        fernet = Fernet(key)

        with open(self._filename, 'rb') as file:
            data = file.read()
            encrypted_data = fernet.encrypt(data)

        with open(salt_filename, 'wb') as file:
            file.write(salt)

        return encrypted_data

    def decrypt(self, password, salt_filename):
        with open(salt_filename, 'rb') as file:
            salt = file.read()

        key = self._generate_key(password, salt)[1]
        fernet = Fernet(key)

        with open(self._filename, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        return decrypted_data

    def _generate_key(self, password, salt=None):
        if salt is None:
            # Generate a new salt
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return salt, key

# Check command-line arguments
if len(sys.argv) < 5:
    print("Usage: python filelock.py [encrypt|decrypt] filename password salt_filename")
    sys.exit(1)

command = sys.argv[1]
filename = sys.argv[2]
password = sys.argv[3]
salt_filename = sys.argv[4]

encrypter = FileEncrypter(filename)

if command == "encrypt":
    encrypted_data = encrypter.encrypt(password, salt_filename)
    encrypted_filename = filename + ".encrypted"
    with open(encrypted_filename, 'wb') as file:
        file.write(encrypted_data)
    print(f"File encrypted successfully. Encrypted file: {encrypted_filename}, Salt file: {salt_filename}")
elif command == "decrypt":
    decrypted_data = encrypter.decrypt(password, salt_filename)
    decrypted_filename = filename + ".decrypted"
    with open(decrypted_filename, 'wb') as file:
        file.write(decrypted_data)
    print(f"File decrypted successfully. Decrypted file: {decrypted_filename}")
else:
    print("Invalid command. Use 'encrypt' or 'decrypt'.")
