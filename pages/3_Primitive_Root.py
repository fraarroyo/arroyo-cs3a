import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

# Generate a symmetric key
def generate_symmetric_key():
    return Fernet.generate_key()

# Symmetric encryption of text
def symmetric_text_encrypt(plaintext, key=None):
    if key is None:
        key = generate_symmetric_key()
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext, key.decode()

def symmetric_text_decrypt(encrypted_text, key):
    try:
        cipher_suite = Fernet(key)
        decrypted_bytes = cipher_suite.decrypt(encrypted_text)
        return decrypted_bytes.decode()
    except (InvalidToken, binascii.Error):
        return "Error: Invalid token or key"

def asymmetric_text_encrypt(plaintext, public_key=None):
    try:
        if public_key is None:
            asymmetric_key_size = 2048  # Default key size
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=asymmetric_key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()

        cipher_text = public_key.encrypt(
            plaintext.encode(),
            padding.PKCS1v15()
        )
        return cipher_text  # Return encrypted bytes
    except Exception as e:
        return f"Error: {e}"

def asymmetric_text_decrypt(ciphertext, private_key=None):
    try:
        if private_key is None:
            return "Error: Private key is required for decryption."
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        ).decode()
        return plaintext
    except Exception as e:
        return f"Error: {e}"

def main():
    st.title("Applied Cryptography Application")
    st.write("Welcome to the Applied Cryptography Application. This app allows you to encrypt, decrypt, and hash messages and files using various cryptographic techniques.")

    symmetric_key = st.sidebar.text_input("Enter symmetric key (32 bytes):")
    if not symmetric_key:
        symmetric_key = generate_symmetric_key()

    asymmetric_key_size = st.sidebar.selectbox("Select asymmetric key size:", (1024, 2048, 4096))
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=asymmetric_key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    options = st.sidebar.radio("Choose an option:", ("Symmetric Encryption (Text)", "Symmetric Encryption (File)", 
                                                     "Symmetric Decryption (Text)", "Asymmetric Encryption (Text)", 
                                                     "Asymmetric Decryption (Text)", "Hashing (Text)", "Hashing (File)"))

    if options == "Symmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text, key = symmetric_text_encrypt(text, symmetric_key)
            st.write("Encrypted Text:", encrypted_text.decode())
            st.write("Key:", key)

    elif options == "Symmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = symmetric_text_decrypt(encrypted_text.encode(), symmetric_key.encode())
            st.write("Decrypted Text:", decrypted_text)

    elif options == "Asymmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = asymmetric_text_encrypt(text, public_key)
            st.write("Encrypted Text:", base64.b64encode(encrypted_text).decode())

    elif options == "Asymmetric Decryption (Text)":
        text = st.text_area("Enter ciphertext to decrypt:")
        if st.button("Decrypt"):
            ciphertext = base64.b64decode(text)
            decrypted_text = asymmetric_text_decrypt(ciphertext, private_key)
            st.write("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
