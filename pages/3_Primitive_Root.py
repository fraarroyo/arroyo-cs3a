import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from cryptography.fernet.InvalidToken import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from io import BytesIO

# Symmetric encryption of text
def symmetric_text_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext

# Symmetric decryption of text
def symmetric_text_decrypt(ciphertext, key):
    try:
        cipher_suite = Fernet(key)
        plaintext = cipher_suite.decrypt(ciphertext).decode()
        return plaintext
    except InvalidToken:
        return "Error: Invalid token or key"

# Symmetric encryption of file
def symmetric_file_encrypt(file_content, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(file_content)
    return ciphertext

# Asymmetric encryption of text
def asymmetric_text_encrypt(plaintext, public_key):
    cipher_text = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

# Asymmetric decryption of text
def asymmetric_text_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return plaintext

# Hashing a text input
def hash_text(text, algorithm):
    if algorithm == "MD5":
        hasher = hashlib.md5()
    elif algorithm == "SHA-1":
        hasher = hashlib.sha1()
    elif algorithm == "SHA-256":
        hasher = hashlib.sha256()
    elif algorithm == "SHA-512":
        hasher = hashlib.sha512()
    hasher.update(text.encode())
    return hasher.hexdigest()

# Hashing a file
def hash_file(file_content, algorithm):
    if algorithm == "MD5":
        hasher = hashlib.md5()
    elif algorithm == "SHA-1":
        hasher = hashlib.sha1()
    elif algorithm == "SHA-256":
        hasher = hashlib.sha256()
    elif algorithm == "SHA-512":
        hasher = hashlib.sha512()
    hasher.update(file_content)
    return hasher.hexdigest()

# Helper function to read file content as bytes
def read_file_content(file):
    file_content = file.read()
    return file_content

def main():
    st.title("Encryption and Hashing App")
    st.write("This app provides symmetric and asymmetric encryption, as well as hashing functions.")

    symmetric_key = st.sidebar.text_input("Enter symmetric key (32 bytes):")
    if not symmetric_key:
        symmetric_key = Fernet.generate_key()

    asymmetric_key_size = st.sidebar.selectbox("Select asymmetric key size:", (1024, 2048, 4096))
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=asymmetric_key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    options = st.sidebar.radio("Choose an option:", ("Symmetric Encryption (Text)", "Symmetric Encryption (File)",
                                                     "Symmetric Decryption (Text)", "Asymmetric Encryption (Text)",
                                                     "Asymmetric Decryption (Text)", "Hashing (Text)",
                                                     "Hashing (File)"))

    if options == "Symmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = symmetric_text_encrypt(text, symmetric_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Symmetric Encryption (File)":
        file = st.file_uploader("Upload file to encrypt:", type=["txt", "pdf"])
        if st.button("Encrypt"):
            if file:
                file_content = read_file_content(file)  # Read file content
                encrypted_file = symmetric_file_encrypt(file_content, symmetric_key)
                st.write("File Encrypted Successfully!")
                st.download_button("Download Encrypted File", encrypted_file, file_name="encrypted_file")

    elif options == "Symmetric Decryption (Text)":
        ciphertext = st.text_area("Enter ciphertext to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = symmetric_text_decrypt(ciphertext, symmetric_key)
            st.write("Decrypted Text:", decrypted_text)

    elif options == "Asymmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = asymmetric_text_encrypt(text, public_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Asymmetric Decryption (Text)":
        ciphertext = st.text_area("Enter ciphertext to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = asymmetric_text_decrypt(ciphertext, private_key)
            st.write("Decrypted Text:", decrypted_text)

    elif options == "Hashing (Text)":
        text = st.text_area("Enter text to hash:")
        algorithm = st.selectbox("Select hashing algorithm:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))
        if st.button("Hash"):
            hashed_text = hash_text(text, algorithm)
            st.write(f"Hashed Text (Algorithm: {algorithm}):", hashed_text)

    elif options == "Hashing (File)":
        file = st.file_uploader("Upload file to hash:", type=["txt", "pdf"])
        algorithm = st.selectbox("Select hashing algorithm:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))
        if st.button("Hash"):
            if file:
                file_content = read_file_content(file)  # Read file content
                hashed_file = hash_file(file_content, algorithm)
                st.write(f"File Hashed Successfully! (Algorithm: {algorithm}):", hashed_file)

if __name__ == "__main__":
    main()
