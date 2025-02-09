from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Generate a random 256-bit (32-byte) key and 128-bit (16-byte) IV
key = os.urandom(32)
iv = os.urandom(16)

# Function to create a sample plaintext.txt file
def create_plaintext_file():
    sample_text = "This is a sample file for AES encryption and decryption."
    with open('plaintext.txt', 'w') as f:
        f.write(sample_text)
    print("Sample plaintext.txt created with sample content.")

# Function to encrypt a file using AES
def encrypt_file(input_file, output_file, key, iv):
    try:
        # Initialize the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Read the plaintext from the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Pad the plaintext to be a multiple of the block size (128 bits for AES)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Write the IV and ciphertext to the output file
        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)

        print(f"File '{input_file}' encrypted successfully to '{output_file}'.")
        print(f"Encrypted file saved at: {os.path.abspath(output_file)}")  # Print full path
    except Exception as e:
        print(f"Error during encryption: {e}")

# Function to decrypt a file using AES
def decrypt_file(input_file, output_file, key):
    try:
        # Read the IV and ciphertext from the input file
        with open(input_file, 'rb') as f:
            iv = f.read(16)  # First 16 bytes are the IV
            ciphertext = f.read()  # The rest is the ciphertext

        # Initialize the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Write the plaintext to the output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"File '{input_file}' decrypted successfully to '{output_file}'.")
        print(f"Decrypted file saved at: {os.path.abspath(output_file)}")  # Print full path
    except Exception as e:
        print(f"Error during decryption: {e}")

# Main execution
if __name__ == "__main__":
    # Create the sample plaintext.txt file
    create_plaintext_file()

    # Define file names
    input_file = 'plaintext.txt'  # Input file to be encrypted
    encrypted_file = 'encrypted.bin'  # Output encrypted file
    decrypted_file = 'decrypted.txt'  # Output decrypted file

    # Encrypt the file
    encrypt_file(input_file, encrypted_file, key, iv)

    # Decrypt the file
    decrypt_file(encrypted_file, decrypted_file, key)
