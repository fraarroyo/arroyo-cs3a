import streamlit as st

# Set page title and icon
st.set_page_config(page_title="Cryptography App", page_icon="🔒")

# Title and description
st.title("Welcome to Cryptography App")
st.write("""
This is a simple web application for cryptography operations. You can perform various cryptographic techniques such as encryption, decryption, and hashing.

Please select an option from the sidebar to get started!
""")

# Sidebar navigation
st.sidebar.title("Navigation")
selected_page = st.sidebar.selectbox("Go to", ["Home", "Text Encryption/Decryption", "File Encryption/Decryption"])

# Conditional content based on selected page
if selected_page == "Text Encryption/Decryption":
    st.write("You selected Text Encryption/Decryption. Here you can encrypt or decrypt text using different cryptographic techniques.")
    # Add your text encryption/decryption form and logic here
elif selected_page == "File Encryption/Decryption":
    st.write("You selected File Encryption/Decryption. Here you can encrypt or decrypt files using different cryptographic techniques.")
    # Add your file encryption/decryption form and logic here
else:
    st.write("You are on the homepage. Please select an option from the sidebar to get started.")
