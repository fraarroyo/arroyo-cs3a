import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding, hashes
import base64

# Generate a symmetric key
def generate_symmetric_key():
    key = Fernet.generate_key()
    return key

# Symmetric encryption of text
def symmetric_text_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext

# Symmetric decryption of text
def symmetric_text_decrypt(encrypted_text, key):
    try:
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
        return decrypted_text
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
        st.sidebar.write("Generated Symmetric Key:", symmetric_key)

    asymmetric_key_size = st.sidebar.selectbox("Select asymmetric key size:", (1024, 2048, 4096))
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=asymmetric_key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    options = st.sidebar.radio("Choose an option:", ("Symmetric Encryption (Text)", "Symmetric Decryption (Text)"))

    if options == "Symmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = symmetric_text_encrypt(text, symmetric_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Symmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = symmetric_text_decrypt(encrypted_text, symmetric_key)
            st.write("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
