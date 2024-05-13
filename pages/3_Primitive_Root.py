import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

st.header("Applied Cryptography Application")

# Caesar Cipher
def caesar_cipher(text, shift_key, if_decrypt):
    """Encrypts or decrypts text using the Caesar Cipher.

    Args:
        text: The text to process.
        shift_key: Integer shift value.
        if_decrypt: True for decryption, False for encryption.

    Returns:
        The processed text.
    """
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
    return result

# Symmetric Encryption (Fernet)
def symmetric_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption.

    Args:
        text: The text to process.
        key: The encryption key.
        if_decrypt: True for decryption, False for encryption.

    Returns:
        The processed text.
    """
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode()
    else:
        return fernet.encrypt(text.encode()).decode()

# Hashing Functions
def hash_text(text, algorithm):
    """Hashes the text using the specified algorithm.

    Args:
        text: The text to hash.
        algorithm: The hashing algorithm.

    Returns:
        The hashed text.
    """
    digest = hashes.Hash(algorithm(), backend=default_backend())
    digest.update(text.encode())
    hashed_text = digest.finalize()
    return hashed_text.hex()

# Streamlit UI setup
crypto_options = ["Caesar Cipher", "Symmetric Encryption (Fernet)", "Hashing"]
selected_crypto = st.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto == "Caesar Cipher":
    st.subheader("Caesar Cipher")
    text = st.text_input("Text")
    shift_key = st.number_input("Shift Key", min_value=1, max_value=25, step=1)
    if_decrypt = st.checkbox("Decrypt")
    if st.button("Submit"):
        if not text:
            st.error("Please enter text.")
        else:
            processed_text = caesar_cipher(text, shift_key, if_decrypt)
            st.write("Processed Text:", processed_text)

elif selected_crypto == "Symmetric Encryption (Fernet)":
    st.subheader("Symmetric Encryption (Fernet)")
    text = st.text_input("Text")
    key = st.text_input("Encryption Key")
    if_decrypt = st.checkbox("Decrypt")
    if st.button("Submit"):
        if not text or not key:
            st.error("Please enter text and encryption key.")
        else:
            processed_text = symmetric_encrypt_decrypt(text, key.encode(), if_decrypt)
            st.write("Processed Text:", processed_text)

elif selected_crypto == "Hashing":
    st.subheader("Hashing")
    text = st.text_input("Text")
    algorithm = st.selectbox("Select Hashing Algorithm", ["SHA-256", "SHA-512", "MD5"])
    if st.button("Submit"):
        if not text:
            st.error("Please enter text.")
        else:
            hashed_text = hash_text(text, getattr(hashes, algorithm))
            st.write("Hashed Text:", hashed_text)
