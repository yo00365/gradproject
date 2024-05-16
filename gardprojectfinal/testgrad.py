import random
import os
import json
import base64
import subprocess
import logging
import re
from flask import Flask, request, render_template, jsonify, redirect, url_for, session
from flask_session import Session  # Import Flask-Session
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Initialize Flask app
app = Flask(__name__)

# Configure Flask-Session to use filesystem session storage
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Directory to store keys and user data
KEY_DIR = "keys"
USER_DATA_DIR = "user_data"
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(USER_DATA_DIR, exist_ok=True)

# Define logger
logger = logging.getLogger(__name__)

def get_device_information():
    """
    Function to retrieve device information using the tpmtool command-line utility.
    """
    try:
        result = subprocess.run(["tpmtool", "getdeviceinformation"], capture_output=True, text=True)
        if result.returncode == 0:
            device_info = result.stdout
            print("Device information gathered successfully:")
            print(device_info)
            logger.info("Device information gathered successfully:")
            logger.info(device_info)
            return device_info  # Return device information
        else:
            print("Error gathering device information:")
            print(result.stderr)
            logger.error("Error gathering device information:")
            logger.error(result.stderr)
            return None
    except FileNotFoundError:
        print("Error: tpmtool command-line utility not found. Make sure it is installed and accessible.")
        logger.error("Error: tpmtool command-line utility not found. Make sure it is installed and accessible.")
        return None

def generate_rsa_keypair():
    """
    Function to generate RSA key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def store_key_in_tpm(private_key, public_key, private_key_pem):
    """
    Function to store private key in TPM (Trusted Platform Module).
    """
    try:
        private_key_str = private_key_pem.decode()

        with open("private_key.pem", "w") as f:
            f.write(private_key_str)

        powershell_command = '''
$Cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
    -Subject "CN=MyTPMKey" -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.21.10.2") `
    -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(10) `
    -CertStoreLocation Cert:\\CurrentUser\\My;
Export-PfxCertificate -Cert $Cert -FilePath "private_key.pfx" -Password (ConvertTo-SecureString -String "password" -AsPlainText -Force);
Import-TpmOwnerAuth -OwnerAuth (ConvertTo-SecureString -String "password" -AsPlainText -Force);
'''

        result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("Private key stored in TPM successfully.")

            # Fetch public key and private key after storing them
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            logger.info("Public key:")
            logger.info(public_key_bytes.decode())  # Decode public key bytes to string for logging
            logger.info("Private key:")
            logger.info(private_key_bytes.decode())  # Decode private key bytes to string for logging

            # Log private_key.pfx content
            with open("private_key.pfx", "rb") as f:
                pfx_content = f.read()
                logger.info("Private key PFX content:")
                logger.info(base64.b64encode(pfx_content).decode())

            return True
        else:
            logger.error("Error storing private key in TPM:")
            logger.error(result.stderr)
            return False
    except FileNotFoundError:
        logger.error("Error: PowerShell or private_key.pem file not found. Make sure PowerShell is installed and accessible.")
        return False

def save_key_to_file(key, filename):
    """
    Function to save key to a file.
    """
    with open(filename, "wb") as f:
        f.write(key)

def load_key_from_file(filename):
    """
    Function to load key from a file.
    """
    with open(filename, "rb") as f:
        return f.read()

def encrypt_message(message, public_key):
    """
    Function to encrypt a message using RSA public key.
    """
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(ciphertext, private_key):
    """
    Function to decrypt a message using RSA private key.
    """
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def generate_math_challenge():
    """
    Function to generate a random mathematical challenge.
    """
    # Generate two random numbers
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)

    # Generate a random operator
    operators = ['+', '-', '*']
    operator = random.choice(operators)

    # Calculate the correct answer
    if operator == '+':
        answer = num1 + num2
    elif operator == '-':
        answer = num1 - num2
    else:
        answer = num1 * num2

    # Create the challenge string
    challenge = f"What is {num1} {operator} {num2}?"

    return challenge, str(answer)

def validate_input(name, email, phone):
    """
    Function to validate user input for registration.
    """
    # Validate email
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False, "Invalid email format"
    if not email.endswith('@gmail.com'):
        return False, "Email domain must be Gmail"

    # Validate phone number
    if not phone.isdigit():
        return False, "Phone number must contain only digits"
    if len(phone) != 11:
        return False, "Phone number must be 11 digits"

    # Validate name
    if not name.isalpha():
        return False, "Name must contain only letters"
    
    return True, "Input is valid"

@app.route("/")
def index():
    """
    Route to render registration page.
    """
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    """
    Route to handle user registration.
    """
    data = request.form
    name = data["name"]
    email = data["email"]
    phone = data["phone"]

    # Validate input
    is_valid, error_message = validate_input(name, email, phone)
    if not is_valid:
        return jsonify({"error": error_message})

    user_id = email.replace("@", "_").replace(".", "_")

    # Check if user already exists
    user_data_filename = os.path.join(USER_DATA_DIR, f"{user_id}.json")
    if os.path.exists(user_data_filename):
        return jsonify({"error": "User already registered"})

    private_key, public_key = main()  # Retrieve both private and public keys from main()

    if private_key is None or public_key is None:
        return jsonify({"error": "Failed to generate keys"})

    private_key_filename = os.path.join(KEY_DIR, f"{user_id}_private.pem")
    public_key_filename = os.path.join(KEY_DIR, f"{user_id}_public.pem")

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    save_key_to_file(private_key_pem, private_key_filename)
    save_key_to_file(public_key_pem, public_key_filename)

    # Save user data to a JSON file
    user_data = {
        "name": name,
        "email": email,
        "phone": phone,
        "public_key_filename": public_key_filename
    }
    with open(user_data_filename, "w") as f:
        json.dump(user_data, f)

    logger.info("User data:")
    logger.info(user_data)

    return redirect(url_for('login'))  # Redirect to login page after registration

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Route to handle user login.
    """
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        data = request.json  # Access JSON data
        email = data["email"]  # Get email from JSON data

        user_id = email.replace("@", "_").replace(".", "_")
        user_data_filename = os.path.join(USER_DATA_DIR, f"{user_id}.json")

        if not os.path.exists(user_data_filename):
            return jsonify({"error": "User not registered"})

        with open(user_data_filename, "r") as f:
            user_data = json.load(f)
        
        public_key_filename = user_data["public_key_filename"]
        public_key_pem = load_key_from_file(public_key_filename)
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Generate a random mathematical challenge
        challenge, correct_answer = generate_math_challenge()

        # Encrypt the challenge using the user's public key
        encrypted_challenge = encrypt_message(challenge, public_key)
        
        # Encode encrypted challenge to base64 before returning as JSON
        encoded_encrypted_challenge = base64.b64encode(encrypted_challenge).decode('utf-8')

        # Store user's email in session
        session['email'] = email

        return jsonify({
            "encrypted_challenge": encoded_encrypted_challenge,
            "question": challenge,
            "correct_answer": correct_answer
        })

@app.route("/verify", methods=["GET", "POST"])
def verify():
    """
    Route to handle verification of user's response to challenge.
    """
    if request.method == "GET":
        # Generate a random mathematical challenge
        challenge, correct_answer = generate_math_challenge()
        
        return render_template("verify.html", question=challenge, correct_answer=correct_answer)
    elif request.method == "POST":
        data = request.form
        user_answer = data.get("answer", "").strip()
        correct_answer = data.get("correct_answer", "").strip()

        if not user_answer or not correct_answer:
            return jsonify({"error": "Answer or correct answer not provided"})

        try:
            user_answer = int(user_answer)
            correct_answer = int(correct_answer)
        except ValueError:
            return jsonify({"error": "Invalid answer or correct answer provided"})

        if user_answer == correct_answer:
            return jsonify({"result": "Correct answer"})
        else:
            return jsonify({"result": "Wrong answer"})

def main():
    """
    Main function to orchestrate key generation and storage.
    """
    # Get device information
    device_info = get_device_information()

    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Store private key in TPM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Pass private and public keys to store in TPM
    store_key_in_tpm(private_key, public_key, private_key_pem)

    return private_key, public_key  # Return both private and public keys

if __name__ == "__main__":
    app.run(debug=True)
