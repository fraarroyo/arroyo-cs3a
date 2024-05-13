import streamlit as st
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

# Function to generate RSA keys
def generate_rsa_keys():
    """Generates RSA public and private keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt or decrypt using RSA
def rsa_encrypt_decrypt(text, if_decrypt, public_key=None):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if not public_key:
        private_key, public_key = generate_rsa_keys()
        st.write("Generated RSA Public Key:", public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        st.write("Generated RSA Private Key:", private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode())
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

# Streamlit UI setup
crypto_options = ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption", 
                  "SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])

# Display keys at the top
if selected_crypto == "RSA Asymmetric Encryption":
    st.write("RSA Keys:")
    private_key_display = st.empty()
    public_key_display = st.empty()
    private_key, public_key = generate_rsa_keys()
    private_key_display.text_area("Private Key", value=private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode(), height=150)
    public_key_display.text_area("Public Key", value=public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), height=150)

# Input fields based on selected crypto
if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
    text = st.text_area("Enter Text")
    if selected_crypto == "Fernet Symmetric Encryption":
        key = st.text_input("Enter Encryption Key")
    if selected_crypto == "RSA Asymmetric Encryption":
        if_decrypt = st.checkbox("Decrypt")

# Text area for hash functions
if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
    text = st.text_area("Enter Text")

# Perform operation on button click
if st.button("Submit"):
    if selected_crypto == "RSA Asymmetric Encryption":
        processed_text, _, _ = rsa_encrypt_decrypt(text, if_decrypt, public_key)
    # Add cases for other cryptographic techniques
    else:
        processed_text = "Not implemented yet"

    st.write("Processed Text:", processed_text)
