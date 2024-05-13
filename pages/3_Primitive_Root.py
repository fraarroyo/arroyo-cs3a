import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
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
def fernet_encrypt(text, key):
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode()

def fernet_decrypt(text, key):
    fernet = Fernet(key)
    try:
        return fernet.decrypt(text.encode()).decode()
    except InvalidToken:
        st.error("Invalid token. Failed to decrypt the data.")
        return None

# RSA Asymmetric Encryption
def rsa_encrypt(text, key):
    public_key = serialization.load_pem_public_key(key.encode())
    encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(encrypted_text).decode()

def rsa_decrypt(text, key):
    private_key = serialization.load_pem_private_key(key.encode(), password=None)
    decrypted_text = private_key.decrypt(base64.b64decode(text), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted_text.decode()

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
crypto_options = ["Caesar Cipher", 
                  "Fernet Symmetric Encryption (Encrypt)", 
                  "Fernet Symmetric Decryption", 
                  "RSA Asymmetric Encryption (Encrypt)", 
                  "RSA Asymmetric Decryption", 
                  "SHA-1 Hashing", 
                  "SHA-256 Hashing", 
                  "SHA-512 Hashing", 
                  "MD5 Hashing"]
selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])

if selected_crypto == "Caesar Cipher":
    text = st.text_area("Enter Text")
    shift_key = st.number_input("Shift Key", min_value=1, max_value=25, step=1, value=3)
    if_decrypt = st.checkbox("Decrypt")

if selected_crypto.startswith("Fernet Symmetric Encryption"):
    text = st.text_area("Enter Text")
    generate_key = selected_crypto.endswith("(Encrypt)")
    if generate_key:
        generated_key = generate_fernet_key()
        st.write("Generated Secret Key for Encryption:", generated_key.decode())
    else:
        generated_key = st.text_input("Enter Secret Key for Decryption")
        
if selected_crypto.startswith("RSA Asymmetric Encryption"):
    text = st.text_area("Enter Text")
    if_decrypt = selected_crypto.endswith("Decryption")
    key_label = "Public Key (Encryption)" if not if_decrypt else "Private Key (Decryption)"
    key = st.text_area(f"Enter {key_label}")
    
if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
    text = st.text_area("Enter Text")

if st.button("Submit"):
    if selected_crypto == "Caesar Cipher":
        processed_text = caesar_cipher(text, shift_key, if_decrypt)
    elif selected_crypto.startswith("Fernet Symmetric Encryption"):
        if generated_key:
            if selected_crypto.endswith("(Decrypt)"):
                processed_text = fernet_decrypt(text, generated_key)
            else:
                processed_text = fernet_encrypt(text, generated_key)
        else:
            st.error("Please generate a key for encryption.")
    elif selected_crypto.startswith("RSA Asymmetric Encryption"):
        if_decrypt = selected_crypto.endswith("(Decryption)")
        if if_decrypt:
            processed_text = rsa_decrypt(text, key)
        else:
            processed_text = rsa_encrypt(text, key)
    elif selected_crypto.startswith("SHA-1 Hashing"):
        processed_text = sha1_hash(text)
    elif selected_crypto.startswith("SHA-256 Hashing"):
        processed_text = hash_text(text, "sha256")
    elif selected_crypto.startswith("SHA-512 Hashing"):
        processed_text = hash_text(text, "sha512")
    elif selected_crypto.startswith("MD5 Hashing"):
        processed_text = hash_text(text, "md5")

    st.write("Processed Text:", processed_text)
