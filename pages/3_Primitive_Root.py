import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import hashlib

# Generate a symmetric key
def generate_symmetric_key():
    return Fernet.generate_key()

# Symmetric encryption of text
def symmetric_text_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext

def symmetric_text_decrypt(encrypted_text, key):
    try:
        cipher_suite = Fernet(key)
        decrypted_bytes = cipher_suite.decrypt(encrypted_text)
        return decrypted_bytes.decode()  # Assuming the decrypted bytes represent text
    except InvalidToken:
        return "Error: Invalid token or key"

# Helper function to read file content as bytes
def read_file_content(file):
    file_content = file.read()
    return file_content

def main():
    st.title("Applied Cryptography Application")
    st.write("Welcome to the Applied Cryptography Application. This app allows you to encrypt, decrypt, and hash messages and files using various cryptographic techniques.")

    symmetric_key = st.sidebar.text_input("Enter symmetric key (32 bytes):")
    if not symmetric_key:
        symmetric_key = generate_symmetric_key()

    options = st.sidebar.radio("Choose an option:", ("Symmetric Encryption (Text)", "Symmetric Decryption (Text)"))

    if options == "Symmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = symmetric_text_encrypt(text, symmetric_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Symmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = symmetric_text_decrypt(encrypted_text.encode(), symmetric_key)
            st.write("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
