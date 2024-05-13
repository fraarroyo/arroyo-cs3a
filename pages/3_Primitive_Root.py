import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import base64

st.title("Applied Cryptography Application")

# Description for each cryptographic algorithm
descriptions = {
    "Caesar Cipher": "The Caesar Cipher is one of the simplest and most widely known encryption techniques. It is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
    "Fernet Symmetric Encryption": "Fernet is a symmetric encryption algorithm that uses a shared secret key to encrypt and decrypt data. It provides strong encryption and is easy to use.",
    "RSA Asymmetric Encryption": "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a public-private key pair. It is widely used for secure communication and digital signatures.",
    "SHA-1 Hashing": "SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It is commonly used for data integrity verification.",
    "SHA-256 Hashing": "SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is commonly used for data integrity verification.",
    "SHA-512 Hashing": "SHA-512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It provides stronger security than SHA-256.",
    "MD5 Hashing": "MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It is commonly used for checksums and data integrity verification."
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
    return result

# Fernet Symmetric Encryption for text
def fernet_encrypt_decrypt_text(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode(), key
    else:
        return fernet.encrypt(text.encode()).decode(), None

# RSA Asymmetric Encryption for text
def rsa_encrypt_decrypt_text(text, key, if_decrypt):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if if_decrypt:
        private_key = serialization.load_pem_private_key(key.encode(), password=None)
        decrypted_text = private_key.decrypt(base64.b64decode(text), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return decrypted_text.decode(), key
    else:
        public_key = serialization.load_pem_public_key(key.encode())
        encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted_text).decode(), None

# Hashing Functions
def hash_text(text, algorithm):
    """Hashes the text using the specified algorithm."""
    return hashlib.new(algorithm, text.encode()).hexdigest()

# SHA-1 Hashing
def sha1_hash(text):
    """Hashes the text using SHA-1."""
    return hashlib.sha1(text.encode()).hexdigest()

# Function to generate a Fernet key
def generate_fernet_key():
    return Fernet.generate_key()

# Streamlit UI setup
crypto_options = ["Text Encryption / Decryption", "File Encryption / Decryption", "Hashing"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto == "Text Encryption / Decryption":
    st.subheader("Text Encryption and Decryption")
    text = st.text_area("Enter Text")
    selected_algorithm = st.selectbox("Select Encryption Algorithm", ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"])
    if selected_algorithm == "RSA Asymmetric Encryption":
        key = st.text_area("Enter Public Key (Encryption) / Private Key (Decryption)")
    if_decrypt = st.checkbox("Decrypt")

    if st.button("Submit"):
        if selected_algorithm == "Caesar Cipher":
            shift_key = st.number_input("Enter Shift Key", value=1)
            processed_text = caesar_cipher(text, shift_key, if_decrypt)
            st.write("Processed Text:", processed_text)
        elif selected_algorithm == "Fernet Symmetric Encryption":
            if if_decrypt:
                key = st.text_input("Enter Encryption Key")
            else:
                generated_key = generate_fernet_key()
                key = generated_key.decode()
            processed_text, decryption_key = fernet_encrypt_decrypt_text(text, key, if_decrypt)
            if if_decrypt:
                st.write("Decryption Key:", decryption_key)
            st.write("Processed Text:", processed_text)
        elif selected_algorithm == "RSA Asymmetric Encryption":
            processed_text, decryption_key = rsa_encrypt_decrypt_text(text, key, if_decrypt)
            if if_decrypt:
                st.write("Decryption Key:", decryption_key)
            st.write("Processed Text:", processed_text)
