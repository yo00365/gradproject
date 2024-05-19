
# Secure Registration and Login System with TPM Key Storage

This is a secure registration and login system built using Flask, which employs TPM (Trusted Platform Module) for key storage. The application provides the following functionalities:

1. **User Registration**: Users can register by providing their name, email, and phone number. Email validation is performed to ensure it has a Gmail domain, and phone numbers must be 11 digits containing only numeric characters.

2. **User Login**: Registered users can log in by providing their email. Upon login, a mathematical challenge is generated, encrypted using the user's public key, and sent to the client. The user must solve the challenge to authenticate.

3. **Key Generation and TPM Storage**: RSA key pairs (private and public keys) are generated for each user during registration. The private key is stored securely in the TPM using PowerShell commands. Device information is gathered using the `tpmtool` command-line utility.

## Prerequisites

Before running the application, ensure the following are installed and accessible:

- Python 3.x
- Flask
- Flask-Session
- cryptography library
- PowerShell (for Windows) or equivalent shell (for Linux/Mac) for TPM key storage
- `tpmtool` command-line utility for device information retrieval

## Installation

1. Clone this repository to your local machine:

   ```
   git clone https://github.com/your/repository.git
   ```

2. Navigate to the project directory:

   ```
   cd secure-registration-login
   ```

3. Install the required Python dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Ensure `tpmtool` and PowerShell are accessible and configured properly for TPM key storage.

## Usage

1. Run the Flask application:

   ```
   python app.py
   ```

2. Access the application in your web browser at `http://localhost:5000`.

3. Register as a new user by providing your name, email, and phone number.

4. Log in using your registered email. You will receive a mathematical challenge to solve.

5. Solve the challenge and submit your answer for verification.

## Notes

- This application is for demonstration purposes and should not be used in production without appropriate security enhancements and thorough testing.
- Ensure proper error handling and security measures are implemented before deploying the application to a production environment.
- Consult the Flask documentation and respective libraries' documentation for detailed configuration and customization options.
