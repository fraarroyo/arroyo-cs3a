import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os

st.title("Applied Cryptography Application")

# Description for each cryptographic algorithm
descriptions = {
    "Caesar Cipher": "The Caesar Cipher is one of the simplest and most widely known encryption techniques. It is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
    "Fernet Symmetric Encryption": "Fernet is a symmetric encryption algorithm that uses a shared secret key to encrypt and decrypt data. It provides strong encryption and is easy to use.",
    "Custom Symmetric Encryption": "This is a custom symmetric encryption technique.",
}

# Caesar Cipher
def caesar_cipher(text, shift_key, if_decrypt):
    """Encrypts or decrypts text using the Caesar Cipher."""
    result = ""
    for char in text:
        if 32 <= ord(char) <= 125:
            shift = shift_key if not if_decrypt else -shift_key
            new_ascii = ord(char) + shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
            result += chr(new_ascii)
        else:
            result += char
    return result, None, None  # Caesar Cipher doesn't generate keys

# Fernet Symmetric Encryption for Text
def fernet_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key)
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode(), None, None
    else:
        return fernet.encrypt(text.encode()).decode(), key, None

# Custom Symmetric Encryption for Text
def custom_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using custom symmetric encryption."""
    # Implement your custom symmetric encryption logic here
    return text, None, None  # Replace this with your custom encryption logic

# Fernet Symmetric Encryption for Files
def fernet_file_encrypt_decrypt(file_contents, key, if_decrypt):
    """Encrypts or decrypts file contents using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key)
    fernet = Fernet(key)
    if if_decrypt:
        decrypted_contents = fernet.decrypt(file_contents)
        return decrypted_contents, None
    else:
        encrypted_contents = fernet.encrypt(file_contents)
        return encrypted_contents, key

# Custom Symmetric Encryption for Files
def custom_file_encrypt_decrypt(file_contents, key, if_decrypt):
    """Encrypts or decrypts file contents using custom symmetric encryption."""
    # Implement your custom symmetric encryption logic here
    return file_contents, None  # Replace this with your custom encryption logic

# Streamlit UI setup
crypto_options = ["Caesar Cipher", "Fernet Symmetric Encryption", "Custom Symmetric Encryption"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])

if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "Custom Symmetric Encryption"]:
    text = st.text_area("Enter Text")
    if selected_crypto == "Caesar Cipher":
        shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
    if selected_crypto == "Fernet Symmetric Encryption":
        key = st.text_input("Enter Encryption Key")
    elif selected_crypto == "Custom Symmetric Encryption":
        key = st.text_input("Enter Encryption Key")
    if_decrypt = st.checkbox("Decrypt")

if selected_crypto in ["Fernet Symmetric Encryption", "Custom Symmetric Encryption"]:
    if st.checkbox("Text Encryption/Decryption"):
        if selected_crypto == "Fernet Symmetric Encryption":
            processed_text, _, _ = fernet_encrypt_decrypt(text, key, if_decrypt)
        elif selected_crypto == "Custom Symmetric Encryption":
            processed_text, _, _ = custom_encrypt_decrypt(text, key, if_decrypt)

        st.write("Processed Text:", processed_text)

if selected_crypto == "Fernet Symmetric Encryption" and st.checkbox("File Encryption/Decryption"):
    # Add file uploader
    file = st.file_uploader("Upload File")

    # Check if file is uploaded
    if file is not None:
        file_contents = file.read()
        file.seek(0)  # Reset file pointer to beginning

        if st.checkbox("Decrypt"):
            key = st.text_input("Enter Decryption Key")
        else:
            key = st.text_input("Enter Encryption Key")
        
        if_decrypt = st.checkbox("Decrypt")

        processed_file, _ = fernet_file_encrypt_decrypt(file_contents, key, if_decrypt)
        if if_decrypt:
            st.download_button(label="Download Decrypted File", data=processed_file, file_name="decrypted_file.txt", mime="text/plain")
        else:
            st.download_button(label="Download Encrypted File", data=processed_file, file_name="encrypted_file.txt", mime="text/plain")
elif selected_crypto == "Custom Symmetric Encryption" and st.checkbox("File Encryption/Decryption"):
    # Add file uploader
    file = st.file_uploader("Upload File")

    # Check if file is uploaded
    if file is not None:
        file_contents = file.read()
        file.seek(0)  # Reset file pointer to beginning

        if st.checkbox("Decrypt"):
            key = st.text_input("Enter Decryption Key")
        else:
            key = st.text_input("Enter Encryption Key")
        
        if_decrypt = st.checkbox("Decrypt")

        processed_file, _ = custom_file_encrypt_decrypt(file_contents, key, if_decrypt)
        if if_decrypt:
            st.download_button(label="Download Decrypted File", data=processed_file, file_name="decrypted_file.txt", mime="text/plain")
        else:
            st.download_button(label="Download Encrypted File", data=processed_file, file_name="encrypted_file.txt", mime="text/plain")
