
# FileLock: A Simple File Encryption and Decryption Tool


FileLock is a straightforward and easy-to-use tool for file encryption and decryption. 
It utilizes symmetric encryption (Fernet) provided by the 'cryptography' library, and a password-based key derivation function (PBKDF2HMAC) to secure your files. 
The salt used for key generation is stored with the encrypted file ensuring the correct decryption key can always be regenerated with the provided password.


## Installation

This project requires Python 3.6 or later. You can download Python from [here](https://www.python.org/downloads/).

You will also need to install the 'cryptography' library. You can install it using pip:

```
pip install cryptography
```

## Usage

You can use FileLock from the command line as follows:

```
python filelock_modified.py [encrypt|decrypt] filename password
```

Replace `[encrypt|decrypt]` with either 'encrypt' to encrypt a file, or 'decrypt' to decrypt a file. Replace `filename` with the name of the file you want to encrypt or decrypt, and `password` with the password you want to use for encryption or decryption.

When encrypting a file, the encrypted file is saved as `filename.encrypted` with the salt prepended to the encrypted data. 

When decrypting a file, the decrypted file is saved as `filename.decrypted`. The salt is stripped from the encrypted data and used to generate the decryption key.

## Warning

Always remember to handle your original unencrypted files as needed to maintain your data security. After encryption, the original unencrypted file will still remain. It's up to you to manage or remove this as necessary.

## Usage for filelock_modified2v.py

Encrypt a file:
```
python filelock_modified_salt_file.py encrypt filename password salt_filename
```
Decrypt a file:
```
python filelock_modified_salt_file.py decrypt filename.encrypted password salt_filename
```
Replace filename with the name of the file to be encrypted or decrypted, password with the password to use for encryption or decryption, and salt_filename with the name of the file where the salt will be saved during encryption or read from during decryption.

Please remember to handle the original unencrypted file and the salt file as needed to maintain your data security.
