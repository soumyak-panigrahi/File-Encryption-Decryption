import argparse
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def parseFolder(path):
    path = os.path.abspath(path)
    if os.path.isdir(path):
        return path
    else:
        raise Exception("Not a Folder")
    
def parseFile(path):
    path= os.path.abspath(path)
    if os.path.isfile(path):
        return path
    else:
        raise Exception("Not a File")

def is_bytes_string(val):
    return isinstance(val, bytes)

def generate_custom_key(salt, password):
    if not is_bytes_string(salt):
        salt = str.encode(salt)
    if not is_bytes_string(password):
        password = str.encode(password)
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def read_salt(path):
    salt = None
    with open(path, "rb") as salt_file:
        salt = salt_file.read()
    return salt

def write_salt(path, salt):
    with open(path, "wb") as salt_file:
        salt_file.write(salt)
    return salt

def generate_salt(path):
    salt = os.urandom(16)    
    return write_salt(path, salt)

def encrypt_file(output_path,input_path, filename, key):
    cipher_suite = Fernet(key)
    input = os.path.join(input_path, filename)
    with open(input, 'rb') as file:
        plaintext = file.read() 
    encrypted_data = cipher_suite.encrypt(plaintext)
    output = os.path.join(output_path, 'encrypted.' + filename) 
    with open(output, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(output_path, input_path, filename, key):
    cipher_suite = Fernet(key)
    input = os.path.join(input_path, filename)
    with open(input, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read() 
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    output_path = os.path.join(output_path, 'decrypted.' + filename)
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Salt Generation")
    parser.add_argument('-o', '--output', type=str, help='Location of Directory to save the Salt', required=True)
    args = parser.parse_args()
    output = parseFolder(args.output) + "/salt"
    print('Generating Salt')
    generate_salt(output)
    print(f'Generated Salt as {output}')