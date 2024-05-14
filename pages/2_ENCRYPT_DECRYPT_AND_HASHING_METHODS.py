import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os

def homepage():
    st.title("Welcome to Cryptography Toolkit")
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("")
    st.image('data:image/jpeg;base64,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', caption='Sunrise by the mountains')
    st.write("Please select a technique from the sidebar to get started.")

def main():
    st.title("Applied Cryptography Application")

    # Description for each cryptographic algorithm
    descriptions = {
        "Caesar Cipher": "The Caesar Cipher is one of the simplest and most widely known encryption techniques. It is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
        "Fernet Symmetric Encryption": "Fernet is a symmetric encryption algorithm that uses a shared secret key to encrypt and decrypt data. It provides strong encryption and is easy to use.",
        "RSA Asymmetric Encryption": "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a public-private key pair. It is widely used for secure communication and digital signatures.",
        "SHA-1 Hashing": "SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-256 Hashing": "SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-512 Hashing": "SHA-512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It provides stronger security than SHA-256.",
        "MD5 Hashing": "MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It is commonly used for checksums and data integrity verification.",
        "Symmetric File Encryption": "Symmetric encryption technique to encrypt and decrypt files using Fernet."
    }

    # Streamlit UI setup
    crypto_options = ["Homepage", "Caesar Cipher", "Fernet Symmetric Encryption", "Symmetric File Encryption", "RSA Asymmetric Encryption", 
                      "SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]
    selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

    if selected_crypto == "Homepage":
        homepage()
        return

    if selected_crypto in descriptions:
        st.sidebar.subheader(selected_crypto)
        st.sidebar.write(descriptions[selected_crypto])

    if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
        text = st.text_area("Enter Text")
        if selected_crypto == "Caesar Cipher":
            shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
        if selected_crypto == "Fernet Symmetric Encryption":
            key = st.text_input("Enter Encryption Key")
        elif selected_crypto == "RSA Asymmetric Encryption":
            key = st.text_area("Enter Public Key (Encryption) / Private Key (Decryption)")
        if_decrypt = st.checkbox("Decrypt")

    if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
        text_or_file = st.radio("Hash Text or File?", ("Text", "File"))
        if text_or_file == "Text":
            text = st.text_area("Enter Text")
        else:
            file_uploaded = st.file_uploader("Upload a file")
        
    if selected_crypto == "Symmetric File Encryption":
        file_uploaded = st.file_uploader("Upload a file")
        key = st.text_input("Enter Encryption Key")
        if_decrypt = st.checkbox("Decrypt")

    if st.button("Submit"):
        processed_text = ""
        try:
            if selected_crypto == "Caesar Cipher":
                processed_text, _, _ = caesar_cipher(text, shift_key, if_decrypt)
            elif selected_crypto == "Fernet Symmetric Encryption":
                processed_text, _, _ = fernet_encrypt_decrypt(text, key, if_decrypt)
            elif selected_crypto == "RSA Asymmetric Encryption":
                processed_text, _, _ = rsa_encrypt_decrypt(text, key, if_decrypt)
            elif selected_crypto == "SHA-1 Hashing":
                if text_or_file == "Text":
                    processed_text = sha1_hash(text)
                else:
                    processed_text = hash_file(file_uploaded, "sha1")
            elif selected_crypto == "SHA-256 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "sha256")
                else:
                    processed_text = hash_file(file_uploaded, "sha256")
            elif selected_crypto == "SHA-512 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "sha512")
                else:
                    processed_text = hash_file(file_uploaded, "sha512")
            elif selected_crypto == "MD5 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "md5")
                else:
                    processed_text = hash_file(file_uploaded, "md5")
            elif selected_crypto == "Symmetric File Encryption":
                if file_uploaded is not None:
                    original_filename = file_uploaded.name
                    if if_decrypt:
                        decrypted_data, filename = fernet_file_decrypt(file_uploaded, key, original_filename)
                        if decrypted_data:
                            st.download_button("Download Decrypted File", decrypted_data, file_name=filename)
                    else:
                        encrypted_data, file_hash = fernet_file_encrypt(file_uploaded, key)
                        if encrypted_data:
                            st.write(f"Encrypted file hash: {file_hash}")
                            st.download_button("Download Encrypted File", encrypted_data, file_name="Decrypted_" + original_filename)
                else:
                    processed_text = "No file uploaded."

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
        else:
            st.write("Processed Text:", processed_text)

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

def fernet_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key.encode())
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode(), None, None
    else:
        return fernet.encrypt(text.encode()).decode(), key, None

def rsa_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if not key:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = key.public_key()
        # Generate public key and display it
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        st.write("Generated RSA Public Key:")
        st.code(public_key_pem.decode())

        # Generate private key in PKCS#1 format and display it
        private_key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        st.write("Generated RSA Secret Key:")
        st.code(private_key_pem.decode())
    if if_decrypt:
        try:
            private_key = serialization.load_pem_private_key(
                key.encode(),
                password=None,
                backend=default_backend()
            )
            decrypted_text = private_key.decrypt(
                base64.b64decode(text),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            return decrypted_text, None, None
        except Exception as e:
            st.write("Error during decryption:", e)
            return "Decryption Error: " + str(e), None, None  # Return error message
    else:
        if isinstance(key, str):
            key = key.encode()
        public_key = serialization.load_pem_public_key(key)
        encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted_text).decode(), None, key

def hash_text(text, algorithm):
    """Hashes the text using the specified algorithm."""
    return hashlib.new(algorithm, text.encode()).hexdigest()

def sha1_hash(text):
    """Hashes the text using SHA-1."""
    return hashlib.sha1(text.encode()).hexdigest()

def hash_file(file, algorithm):
    """Computes the hash of a file using the specified algorithm."""
    hash_function = hashlib.new(algorithm)
    file.seek(0)  # Ensure we're at the start of the file
    while True:
        data = file.read(65536)  # Read in chunks to conserve memory
        if not data:
            break
        hash_function.update(data)
    file.seek(0)  # Reset file pointer to beginning after hashing
    return hash_function.hexdigest()

def fernet_file_encrypt(file, key):
    """Encrypts a file using Fernet symmetric encryption and computes its hash."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key.encode())
    encrypted_data = fernet.encrypt(file.read())
    file_hash = hashlib.sha256(encrypted_data).hexdigest()
    return encrypted_data, file_hash

def fernet_file_decrypt(file, key, original_filename):
    """Decrypts a file using Fernet symmetric encryption and saves it with the original filename."""
    try:
        fernet = Fernet(key.encode())
        decrypted_data = fernet.decrypt(file.read())
        return decrypted_data, original_filename
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None, None


if __name__ == "__main__":
    main()
