# File Encryption & Decryption

Make sure to install the requirement from `requirement.py`

To Generate the saltfile

- use the script `salt_generation.py`
- Provide the output location as `--output`
- If the Script is executed successfully, a file named `salt` without extension is generated
- You can use this file for Encryption and Decryption, make sure to save it

To Encrypt or Decrypt a file

- Settings
    - Load all your files to Folder, and provide the locationa as `--input`
    - Mention where to store the output as `--output`, make sure it exists
    - Provide format if needed for `--format`
    - Provide the saltfile location as `--saltfile`
    - Mention if Decryption by `--decrypt`, by default encryption is provided
- You will be prompted for `Password`
    - The key will be generated from the provided `password` and the `salt` from the saltfile
    - To successfully encrypt and decrypt the file. Make sure to use the same `saltfile`