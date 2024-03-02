import argparse
import os, glob
from getpass import getpass
from salt_generation import parseFolder, parseFile, generate_custom_key, read_salt , encrypt_file, decrypt_file    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Encrypt~Decrypt",description="Encrypt and Decrypt Files based on Custom Salt and Password")
    
    # Adding arguments
    parser.add_argument('-f', '--format', type=str, help='Format of file to scan from Input, provide as comma separated eg. js,css,html')
    parser.add_argument('-d', '--decrypt', action="store_true", help="Perform Decrypt Operations, the default is Encrypt")
    
    parser.add_argument('-o', '--output', type=str, help='Location to save the Output', required=True)
    parser.add_argument('-i', '--input', type=str, help='Location to fetch the input', required=True)
    parser.add_argument('-s', '--saltfile', type=str, help='Path to the saltfile', required=True)
    
    # Parsing arguments
    args = parser.parse_args()
    
    encrypt = False if args.decrypt else True
    formats = args.format.split(',') if args.format else ['*']
    try:
        input_path = parseFolder(args.input)
        output_path = parseFolder(args.output)
        salt_path = parseFile(args.saltfile)
        saltvalue = read_salt(salt_path)
        password = getpass()
        key = generate_custom_key(saltvalue, password)
        for format in formats:
            for file in glob.glob(os.path.join(input_path, f'*.{format}')):
                filename = os.path.basename(file)
                if encrypt :
                    encrypt_file(output_path,input_path, filename, key)
                else:
                    decrypt_file(output_path, input_path, filename, key)
    except Exception as err:
        print('Error has Occured: ', err)
    

    