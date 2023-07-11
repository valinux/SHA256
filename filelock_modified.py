
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

    def encrypt(self, password):
        if not os.path.exists(self._filename):
            raise ValueError("File does not exist")

        salt, key = self._generate_key(password)
        fernet = Fernet(key)

        with open(self._filename, 'rb') as file:
            data = file.read()
            encrypted_data = fernet.encrypt(data)

        # Prepend the salt to the encrypted data
        return salt + encrypted_data

    def decrypt(self, password):
        with open(self._filename, 'rb') as file:
            data = file.read()

        # Strip off the salt from the data
        salt = data[:16]
        data = data[16:]

        key = self._generate_key(password, salt)[1]
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(data)

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
if len(sys.argv) < 4:
    print("Usage: python filelock.py [encrypt|decrypt] filename password")
    sys.exit(1)

command = sys.argv[1]
filename = sys.argv[2]
password = sys.argv[3]

encrypter = FileEncrypter(filename)

if command == "encrypt":
    encrypted_data = encrypter.encrypt(password)
    encrypted_filename = filename + ".encrypted"
    with open(encrypted_filename, 'wb') as file:
        file.write(encrypted_data)
    print(f"File encrypted successfully. Encrypted file: {encrypted_filename}")
elif command == "decrypt":
    decrypted_data = encrypter.decrypt(password)
    decrypted_filename = filename + ".decrypted"
    with open(decrypted_filename, 'wb') as file:
        file.write(decrypted_data)
    print(f"File decrypted successfully. Decrypted file: {decrypted_filename}")
else:
    print("Invalid command. Use 'encrypt' or 'decrypt'.")
