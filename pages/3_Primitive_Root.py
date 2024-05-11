import streamlit as st
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

# Symmetric Encryption (AES)
st.header("AES Encryption")

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Asymmetric Encryption (RSA)
st.header("RSA Encryption")

def rsa_encrypt(plaintext, public_key):
    cipher = RSA.import_key(public_key)
    return cipher.encrypt(plaintext, None)[0]

def rsa_decrypt(ciphertext, private_key):
    cipher = RSA.import_key(private_key)
    return cipher.decrypt(ciphertext)

# Hashing (SHA-256)
st.header("SHA-256 Hashing")

def sha256_hash(message):
    hash_object = SHA256.new()
    hash_object.update(message)
    return hash_object.hexdigest()

# Streamlit UI
selected_option = st.sidebar.selectbox(
    "Select Cryptographic Operation",
    ("AES Encryption", "AES Decryption", "RSA Encryption", "RSA Decryption", "SHA-256 Hashing")
)

if selected_option == "AES Encryption":
    plaintext = st.text_area("Plain Text:")
    key = st.text_input("Key:")
    if st.button("Encrypt"):
        ciphertext = aes_encrypt(plaintext.encode(), key.encode())
        st.write("Ciphertext:", ciphertext.hex())

if selected_option == "AES Decryption":
    ciphertext = st.text_area("Ciphertext:")
    key = st.text_input("Key:")
    if st.button("Decrypt"):
        plaintext = aes_decrypt(bytes.fromhex(ciphertext), key.encode())
        st.write("Decrypted:", plaintext.decode())

if selected_option == "RSA Encryption":
    plaintext = st.text_area("Plain Text:")
    public_key = st.text_area("Public Key:")
    if st.button("Encrypt"):
        ciphertext = rsa_encrypt(plaintext.encode(), public_key)
        st.write("Ciphertext:", ciphertext.hex())

if selected_option == "RSA Decryption":
    ciphertext = st.text_area("Ciphertext:")
    private_key = st.text_area("Private Key:")
    if st.button("Decrypt"):
        plaintext = rsa_decrypt(bytes.fromhex(ciphertext), private_key)
        st.write("Decrypted:", plaintext.decode())

if selected_option == "SHA-256 Hashing":
    message = st.text_area("Message:")
    if st.button("Hash"):
        hashed_message = sha256_hash(message.encode())
        st.write("Hashed Message:", hashed_message)

st.balloons()
