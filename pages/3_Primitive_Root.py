import streamlit as st
import uuid  # Import UUID library for generating unique identifiers
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import hashlib
import base64
import os

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

# Generate unique IDs for widgets
key_input_id = str(uuid.uuid4()) + "_key_input"
public_key_input_id = str(uuid.uuid4()) + "_public_key_input"

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

# Fernet Symmetric Encryption
def fernet_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode(), None, None
    else:
        return fernet.encrypt(text.encode()).decode(), key.decode(), None

# RSA Asymmetric Encryption
def generate_rsa_public_key():
    """Generates RSA public key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key

def rsa_encrypt_decrypt(text, if_decrypt, public_key=None):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if not public_key:
        public_key = generate_rsa_public_key()
        st.write("Generated RSA Public Key:", public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    if if_decrypt:
        st.error("RSA encryption with only public key is not supported for decryption.")
        return None, None, None
    else:
        encrypted_text = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_text).decode(), public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), None

# Hashing Functions
def hash_text(text, algorithm):
    """Hashes the text using the specified algorithm."""
    return hashlib.new(algorithm, text.encode()).hexdigest()

# SHA-1 Hashing
def sha1_hash(text):
    """Hashes the text using SHA-1."""
    return hashlib.sha1(text.encode()).hexdigest()

# Streamlit UI setup
crypto_options = ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption", 
                  "SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])

# Display secret key and public key at the top of input fields
if selected_crypto == "Fernet Symmetric Encryption":
    key = st.text_input("Enter Encryption Key", key_input_id)
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
elif selected_crypto == "RSA Asymmetric Encryption":
    public_key = st.text_area("Public Key", public_key_input_id)
    if not public_key:
        generated_public_key = generate_rsa_public_key()
        public_key = generated_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        st.write("Generated RSA Public Key:", public_key)

if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
    text = st.text_area("Enter Text")
    if selected_crypto == "Caesar Cipher":
        shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
    if selected_crypto == "Fernet Symmetric Encryption":
        key = st.text_input("Enter Encryption Key", key_input_id)
    elif selected_crypto == "RSA Asymmetric Encryption":
        public_key = st.text_area("Public Key", public_key_input_id)
        st.write("Generated RSA Public Key:", generate_rsa_public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    if_decrypt = st.checkbox("Decrypt")

if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
    text = st.text_area("Enter Text")

if st.button("Submit"):
    if selected_crypto == "Caesar Cipher":
        processed_text, _, _ = caesar_cipher(text, shift_key, if_decrypt)
    elif selected_crypto == "Fernet Symmetric Encryption":
        processed_text, _, _ = fernet_encrypt_decrypt(text, key, if_decrypt)
    elif selected_crypto == "RSA Asymmetric Encryption":
        processed_text, _, _ = rsa_encrypt_decrypt(text, if_decrypt, public_key)
    elif selected_crypto == "SHA-1 Hashing":
        processed_text = sha1_hash(text)
    elif selected_crypto == "SHA-256 Hashing":
        processed_text = hash_text(text, "sha256")
    elif selected_crypto == "SHA-512 Hashing":
        processed_text = hash_text(text, "sha512")
    elif selected_crypto == "MD5 Hashing":
        processed_text = hash_text(text, "md5")

    st.write("Processed Text:", processed_text)
