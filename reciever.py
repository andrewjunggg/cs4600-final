from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256

# fetch our private key
with open('./reciever_key/reciever_private_key.pem', 'r') as file:
   private_key = RSA.import_key( file.read() )

# sizes of transmitted data in bytes
AES_KEY_SIZE = private_key.size_in_bytes()
NONCE_SIZE = 16
MAC_KEY_SIZE = private_key.size_in_bytes()
MAC_SIZE = 32

# retrieve encrypted aes and mac keys, nonce and ciphertext from local file
with open('./transmitted_data.bin', 'rb') as file:
   encrypted_aes_key, encrypted_mac_key, transmitted_mac_tag, nonce, ciphertext  = \
      [ file.read(x) for x in (private_key.size_in_bytes(), MAC_KEY_SIZE, MAC_SIZE, NONCE_SIZE, -1)]


# decrypt the encrypted aes_key with private key
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# decrypt the encrypted mag key with private key
mac_key = cipher_rsa.decrypt(encrypted_mac_key)

# create aes cipher with the decrypted aes key
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

# generate our mag tag with the decrypted mac_key and the nonce + ciphertext
mac = HMAC.new(mac_key, digestmod=SHA256)
mac.update(nonce + ciphertext)

# verify the mac tags
try:
   mac.verify(transmitted_mac_tag)
   print("Recieved ciphertext is authentic\n")
except ValueError:
   print("Ciphertext or key is invalid")
   raise SystemExit # exit script on Value error

print("----Decrypted ciphertext----")
print( cipher_aes.decrypt(ciphertext).decode('utf-8') )