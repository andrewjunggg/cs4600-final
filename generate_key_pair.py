from Crypto.PublicKey import RSA
import os

# 2048 bit (256 byte) key size
KEY_SIZE = 2048

def generate_keys(party_name):
   key_pair = RSA.generate(KEY_SIZE)

   private_file = './{0}_key/{0}_private_key.pem'.format(party_name)
   os.makedirs(os.path.dirname(private_file), exist_ok=True)
   with open(private_file, 'wb') as file:
      file.write( key_pair.export_key('PEM') )

   public_file = './public_keys/{0}_public_key.pem'.format(party_name)
   os.makedirs(os.path.dirname(public_file), exist_ok=True)
   with open(public_file, 'wb') as file:
      file.write( key_pair.publickey().export_key('PEM') )

generate_keys('sender')
generate_keys('reciever')