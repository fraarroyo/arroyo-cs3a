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

# Fernet Symmetric Encryption
def fernet_encrypt_decrypt_text(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode()
    else:
        return fernet.encrypt(text.encode()).decode()

# Fernet Symmetric Encryption for file
def fernet_encrypt_decrypt_file(file_content, key, if_decrypt):
    """Encrypts or decrypts file content using the Fernet symmetric encryption."""
    fernet = Fernet(key)
    if if_decrypt:
        return fernet.decrypt(file_content)
    else:
        return fernet.encrypt(file_content)

# RSA Asymmetric Encryption
def rsa_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if if_decrypt:
        private_key = serialization.load_pem_private_key(key.encode(), password=None)
        decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return decrypted_text.decode()
    else:
        public_key = serialization.load_pem_public_key(key.encode())
        encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted_text).decode()

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
crypto_options = ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption", 
                  "SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])

file = st.file_uploader("Upload File")

if selected_crypto in ["Caesar Cipher", "RSA Asymmetric Encryption"]:
    text = st.text_area("Enter Text")
    if selected_crypto == "RSA Asymmetric Encryption":
        key = st.text_area("Enter Public Key (Encryption) / Private Key (Decryption)")

if selected_crypto == "Fernet Symmetric Encryption":
    st.subheader("Fernet Symmetric Encryption")
    st.write("To encrypt or decrypt using Fernet Symmetric Encryption, you need to provide a secret key.")
    st.write("Here is the generated secret key:")
    generated_key = generate_fernet_key()
    st.write(generated_key.decode())
    text = st.text_area("Enter Text")
    key = st.text_input("Enter Encryption Key (Use the generated key)")

if selected_crypto in ["Caesar Cipher", "RSA Asymmetric Encryption", "Fernet Symmetric Encryption"]:
    if_decrypt = st.checkbox("Decrypt")

if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
    text = st.text_area("Enter Text")

if st.button("Submit"):
    if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
        if file:
            file_content = file.read()
        else:
            file_content = None

    if selected_crypto == "Caesar Cipher":
        shift_key = st.number_input("Enter Shift Key", value=1)
        processed_text = caesar_cipher(text, shift_key, if_decrypt)
        processed_file_content = caesar_cipher(file_content.decode(), shift_key, if_decrypt) if file_content else None
    elif selected_crypto == "Fernet Symmetric Encryption":
        processed_text = fernet_encrypt_decrypt_text(text, key, if_decrypt)
        processed_file_content = fernet_encrypt_decrypt_file(file_content, key, if_decrypt) if file_content else None
    elif selected_crypto == "RSA Asymmetric Encryption":
        processed_text = rsa_encrypt_decrypt(text, key, if_decrypt)
        processed_file_content = None  # RSA doesn't directly support file encryption/decryption
    elif selected_crypto == "SHA-1 Hashing":
        processed_text = sha1_hash(text)
        processed_file_content = None
    elif selected_crypto == "SHA-256 Hashing":
        processed_text = hash_text(text, "sha256")
        processed_file_content = None
    elif selected_crypto == "SHA-512 Hashing":
        processed_text = hash_text(text, "sha512")
        processed_file_content = None
    elif selected_crypto == "MD5 Hashing":
        processed_text = hash_text(text, "md5")
        processed_file_content = None

    st.write("Processed Text:", processed_text)
    if file_content and processed_file_content:
        st.write("Processed File Content:", processed_file_content.decode())
