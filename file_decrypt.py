import argparse, os, glob, base64
from getpass import getpass
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

def decrypt_file(output_path, input_path, filename, key):
    cipher_suite = Fernet(key)
    input = os.path.join(input_path, filename)
    with open(input, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read() 
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    output_path = os.path.join(output_path, filename)
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

def get_password():
    ps, cps = '1', '2'
    while not ps == cps:
        ps=str(getpass("Password:"))
        cps=str(getpass("Confirm Password:"))
    return ps

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Decryptor",description="Decrypt Files based on Custom Salt and Password")
    
    # Adding arguments
    parser.add_argument('-f', '--format', type=str, help='Format of file to scan from Input, provide as comma separated eg. js,css,html')
    parser.add_argument('-o', '--output', type=str, help='Folder Location to save the Output', required=True)
    parser.add_argument('-i', '--input', type=str, help='Folder Location to fetch the input', required=True)
    parser.add_argument('-s', '--saltfile', type=str, help='Path to the saltfile', required=True)
    
    # Parsing arguments
    args = parser.parse_args()
    try:
        formats = args.format.split(',') if args.format else ['*']
        input_path = parseFolder(args.input)
        output_path = parseFolder(args.output)
        salt_path = parseFile(args.saltfile)
        saltvalue = read_salt(salt_path)
        password = get_password()
        key = generate_custom_key(saltvalue, password)
        for format in formats:
            for file in glob.glob(os.path.join(input_path, f'*.{format}')):
                filename = os.path.basename(file)
                decrypt_file(output_path, input_path, filename, key)
                print('Decrypted:' + filename)
    except Exception as err:
        print('Error has Occured:', err)
    