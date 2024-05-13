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
        if isinstance(encrypted_text, str):
            encrypted_text = encrypted_text.encode()
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
        return decrypted_text
    except InvalidToken:
        return None  # Return None for invalid token or key

def symmetric_file_encrypt(file_content, key):
    """Symmetric encryption of file."""
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(file_content)
    return ciphertext

def symmetric_file_decrypt(encrypted_file, key):
    """Symmetric decryption of file."""
    try:
        cipher_suite = Fernet(key)
        decrypted_file = cipher_suite.decrypt(encrypted_file)
        return decrypted_file
    except InvalidToken:
        return None

def asymmetric_text_encrypt(plaintext, public_key):
    """Asymmetric encryption of text."""
    cipher_text = public_key.encrypt(
        plaintext.encode(),
        padding.PKCS1v15()
    )
    return base64.b64encode(cipher_text).decode()

def asymmetric_text_decrypt(ciphertext, private_key):
    """Asymmetric decryption of text."""
    try:
        ciphertext_bytes = base64.b64decode(ciphertext.encode())
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.PKCS1v15()
        ).decode()
        return plaintext
    except Exception as e:
        return f"Error: {e}"

def hash_text(text, algorithm):
    """Hashing a text input."""
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode())
    return hasher.hexdigest()

def hash_file(file_content, algorithm):
    """Hashing a file."""
    hasher = hashlib.new(algorithm)
    hasher.update(file_content)
    return hasher.hexdigest()

def read_file_content(file):
    """Helper function to read file content as bytes."""
    return file.read()

def main():
    st.title("Applied Cryptography Application")
    st.write("Welcome to the Applied Cryptography Application. This app allows you to encrypt, decrypt, and hash messages and files using various cryptographic techniques.")

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
            encrypted_text, symmetric_key = symmetric_text_encrypt(text, symmetric_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Symmetric Encryption (File)":
        file = st.file_uploader("Upload file to encrypt:", type=["txt", "pdf"])
        if file is not None:
            file_content = read_file_content(file)
            encrypted_file = symmetric_file_encrypt(file_content, symmetric_key)
            st.write("File Encrypted Successfully!")
            # Download encrypted file
            b64_encoded_file = base64.b64encode(encrypted_file).decode()
            href = f'<a href="data:file/txt;base64,{b64_encoded_file}" download="encrypted_file.txt">Download encrypted file</a>'
            st.markdown(href, unsafe_allow_html=True)

    elif options == "Symmetric Decryption (Text)":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt"):
            try:
                decrypted_text = symmetric_text_decrypt(encrypted_text, symmetric_key)
                if decrypted_text is not None:
                    st.write("Decrypted Text:", decrypted_text)
                else:
                    st.write("Error: Invalid token or key")
            except Exception as e:
                st.write(f"Error: {e}")

    elif options == "Asymmetric Encryption (Text)":
        text = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt"):
            encrypted_text = asymmetric_text_encrypt(text, public_key)
            st.write("Encrypted Text:", encrypted_text)

    elif options == "Asymmetric Decryption (Text)":
        text = st.text_area("Enter ciphertext to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = asymmetric_text_decrypt(text, private_key)
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
                file_content = read_file_content(file)
                hashed_file = hash_file(file_content, algorithm)
                st.write(f"File Hashed Successfully! (Algorithm: {algorithm}):", hashed_file)

if __name__ == "__main__":
    main()
