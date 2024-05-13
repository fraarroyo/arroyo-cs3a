import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding, hashes
import base64

def generate_symmetric_key():
    """Generate a symmetric key."""
    return Fernet.generate_key()

def symmetric_text_encrypt(plaintext, key):
    """Symmetric encryption of text."""
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext, key

def symmetric_text_decrypt(encrypted_text, key):
    """Symmetric decryption of text."""
    try:
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
        return decrypted_text
    except InvalidToken:
        return "Error: Invalid token or key"

def asymmetric_text_encrypt(plaintext, public_key):
    """Asymmetric encryption of text."""
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def asymmetric_text_decrypt(ciphertext, private_key):
    """Asymmetric decryption of text."""
    try:
        ciphertext_bytes = base64.b64decode(ciphertext.encode())
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return plaintext
    except Exception as e:
        return f"Error: {e}"

def hash_text(text, algorithm):
    """Hashing a text input."""
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode())
    return hasher.hexdigest()

def read_file_content(file):
    """Helper function to read file content as bytes."""
    return file.read()

def main():
    st.title("Applied Cryptography Application")
    st.write("Welcome to the Applied Cryptography Application. This app allows you to encrypt, decrypt, and hash messages and files using various cryptographic techniques.")

    symmetric_key = generate_symmetric_key()
    st.sidebar.subheader("Symmetric Key")
    st.sidebar.write("Generated Key:", symmetric_key.decode())
    if st.sidebar.button("Regenerate Key"):
        symmetric_key = generate_symmetric_key()
        st.sidebar.write("New Key Generated:", symmetric_key.decode())

    asymmetric_key_size = st.sidebar.selectbox("Select asymmetric key size:", (1024, 2048, 4096))
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=asymmetric_key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    options = st.sidebar.radio("Choose an option:", ("Symmetric Encryption (Text)", "Symmetric Decryption (Text)", 
                                                     "Asymmetric Encryption (Text)", "Asymmetric Decryption (Text)", 
                                                     "Hashing (Text)"))

    if options == "Symmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            if text:
                encrypted_text, _ = symmetric_text_encrypt(text, symmetric_key)
                st.write("Encrypted Text:", encrypted_text.decode())
            else:
                st.write("Please enter text to encrypt.")

    elif options == "Symmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt"):
            if encrypted_text:
                decrypted_text = symmetric_text_decrypt(encrypted_text.encode(), symmetric_key)
                st.write("Decrypted Text:", decrypted_text)
            else:
                st.write("Please enter text to decrypt.")

    elif options == "Asymmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            if text:
                encrypted_text = asymmetric_text_encrypt(text, public_key)
                st.write("Encrypted Text:", encrypted_text)
            else:
                st.write("Please enter text to encrypt.")

    elif options == "Asymmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter ciphertext to decrypt:")
        if st.button("Decrypt"):
            if encrypted_text:
                decrypted_text = asymmetric_text_decrypt(encrypted_text, private_key)
                st.write("Decrypted Text:", decrypted_text)
            else:
                st.write("Please enter ciphertext to decrypt.")

    elif options == "Hashing (Text)":
        text = st.text_area("Enter text to hash:")
        algorithm = st.selectbox("Select hashing algorithm:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))
        if st.button("Hash"):
            if text:
                hashed_text = hash_text(text, algorithm)
                st.write(f"Hashed Text (Algorithm: {algorithm}):", hashed_text)
            else:
                st.write("Please enter text to hash.")

if __name__ == "__main__":
    main()
