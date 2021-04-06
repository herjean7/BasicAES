# Asymmetric and Symmetric Encryption

In this application, we apply both Asymmetric (Digital Certificates) and Symmetric (AES) Encryptions to safeguard our secrets between 2 applications

**Basics:**

1. [Symmetric] A random pair of Key and IV is generated each time we initialise AES256

2. [Asymmetric] A public key can be used to encrypt a piece of data and only the private key can be used to decrypt the encrypted data

**Steps:**

1. Generate a random pair of AES Key and IV by initialising AES256

2. Encrypt a piece of data using the AES Key and IV generated (cipher text generated)

3. Initialise a byte array and pad the AES Key, IV and cipher text into the byte array

4. Encrypt the byte array using the public key of the digital certificate

5. Send this encrypted byte array to the receiving application

6. The receiving application will first have to decrypt the byte array using the private key of the digital certificate

7. Retrieve the AES Key and IV

8. Decrypt the ciphertext back to plaintext using the AES Key and IV
