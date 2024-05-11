import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding, hashes

# Symmetric encryption of text
def symmetric_text_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext

# Symmetric decryption of text
def symmetric_text_decrypt(encrypted_text, key):
    try:
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
        return decrypted_text
    except InvalidToken:
        return "Error: Invalid token or key"

def main():
    st.title("Symmetric Encryption and Decryption App")
    st.write("This app allows you to encrypt and decrypt text using symmetric encryption.")

    # Input for symmetric key
    symmetric_key = st.text_input("Enter symmetric key (32 bytes):")

    # Input for plaintext
    plaintext = st.text_area("Enter plaintext:")

    if st.button("Encrypt"):
        if not symmetric_key:
            st.error("Please enter a symmetric key.")
        elif not plaintext:
            st.error("Please enter plaintext to encrypt.")
        else:
            encrypted_text = symmetric_text_encrypt(plaintext, symmetric_key)
            st.write("Encrypted Text:", encrypted_text)

    # Decryption section
    st.subheader("Symmetric Decryption")

    # Input for ciphertext
    ciphertext = st.text_area("Enter ciphertext to decrypt:")

    if st.button("Decrypt"):
        if not symmetric_key:
            st.error("Please enter a symmetric key.")
        elif not ciphertext:
            st.error("Please enter ciphertext to decrypt.")
        else:
            decrypted_text = symmetric_text_decrypt(ciphertext.encode(), symmetric_key)
            st.write("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
