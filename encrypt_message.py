from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import hmac
import hashlib

# Step 1. Generate RSA public and private keys
# Step 2. Encrypt the message.txt using AES, and store the AES key
# Step 3. Encrypt the AES key using the receiver's RSA public key.
# The encrypted AES key is sent together with the encrypted message obtained from step 2
# Step 4. Append Message Authentication Code (MAC) to the data that will be transmitted.
# (Free to choose which protocol)
# Step 5. For receiver: receive, authenticate, and decrypt the message.


def encrypt_file(input_file, output_file, key):
    chunk_size = 64 * 1024

    cipher = AES.new(key, AES.MODE_EAX)

    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        outfile.write(cipher.nonce)

        while True:
            chunk = infile.read(chunk_size)
            if len(chunk) == 0:
                break
            ciphertext = cipher.encrypt(chunk)
            outfile.write(ciphertext)

    print(f"Encryption of '{input_file}' to '{output_file}' completed successfully.")


def encrypt_file_key_with_rsa(key, rsa_public_key_file):
    with open(rsa_public_key_file, "r") as f:
        rsa_public_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_key = cipher_rsa.encrypt(key)

    print("Key has been encrypted successfully.")

    return encrypted_key


def generate_hmac(data, key):
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()


def save_to_file(data, file_path):
    with open(file_path, "wb") as f:
        f.write(data)


def main():
    message_input_file = "the_message.txt"
    encrypted_message_output_file = "encrypted_message.bin"

    # Generate a 256-bit (32 bytes) random key
    aes_key = get_random_bytes(32)

    encrypt_file(message_input_file, encrypted_message_output_file, aes_key)

    # Encrypt AES key using RSA
    rsa_public_key_file = "./public_keys/reciever_public_key.pem"

    encrypted_aes = encrypt_file_key_with_rsa(aes_key, rsa_public_key_file)

    encrypted_key_output_file = "encrypted_aes_key.bin"
    save_to_file(encrypted_aes, encrypted_key_output_file)
    print("Encrypted key saved to encrypted_aes_key.bin")

    # Append MAC to the data
    with open("./encrypted_message.bin", "rb") as file:
        encrypted_file_data = file.read()

    mac_key = get_random_bytes(32)
    hmac_digest = generate_hmac(encrypted_file_data, mac_key)

    # encrypt the key used to generate the mac tag
    encrypted_mac_key = encrypt_file_key_with_rsa(mac_key, rsa_public_key_file)

    transmitted_data_output_file = "transmitted_data.bin"
    data_to_transmit = (
        encrypted_aes + encrypted_mac_key + hmac_digest + encrypted_file_data
    )
    save_to_file(data_to_transmit, transmitted_data_output_file)
    print("transmitted_data has been saved successfully.")


if __name__ == "__main__":
    main()
