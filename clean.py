import os

os.remove("encrypted_aes_key.bin")
os.remove("encrypted_message.bin")
os.remove("transmitted_data.bin")

os.remove("./public_keys/receiver_public_key.pem")
os.remove("./public_keys/sender_public_key.pem")
os.rmdir("public_keys")

os.remove("./receiver_key/receiver_private_key.pem")
os.rmdir("receiver_key")
os.remove("./sender_key/sender_private_key.pem")
os.rmdir("sender_key")

print("Files successfully cleaned.")
