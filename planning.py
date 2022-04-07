# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



#  pip install pycryptodome

N4_PORT = 8400
N4_routing = {
    "2a": "N2",  # entry
    "5a": "N5",
}

N5_PORT = 8500
N5_routing = {
    "4a": "N4",
    "6a": "N6",
}

N6_PORT = 8600
N6_routing = {
    "5a": "N5",
    "7a": "N7",
}

N7_PORT = 8700
N7_routing = {
    "3a": "N3",  # exit
    "6a": "N6",
}

onion_path = ["N4", "N5", "N6"]

data = b"N7hello"  # Structure: Dest Addr + Message

class AESCipher:
    def __init__(self, key):
        password = key.encode('utf-8')
        self.key = md5(password).digest()

    def encrypt(self, data):
        vector = get_random_bytes(AES.block_size)
        encryption_cipher = AES.new(self.key, AES.MODE_CBC, vector)
        return vector + encryption_cipher.encrypt(pad(data,  AES.block_size))

    def decrypt(self, data):
        file_vector = data[:AES.block_size]
        decryption_cipher = AES.new(self.key, AES.MODE_CBC, file_vector)
        return unpad(decryption_cipher.decrypt(data[AES.block_size:]), AES.block_size)

def generate_AES_keys(onion_path):
    for node in onion_path:
        key = get_random_bytes(16)
        file_out = open("keys/{node}.pem".format(node=node), "a")
        file_out.write(key)
        file_out.close()
    return

def prepare_onion_packet(onion_path, message):
    
    for n in range(len(onion_path)-1,-1,-1):
        key = open("keys/N{node}.pem".format(node=n)).read()
        # iv = get_random_bytes(AES.block_size)
        encryption_cipher = AES.new(key, AES.MODE_CBC)
        encrypted_message = encryption_cipher.encrypt(pad(data, AES.block_size))

        if n == 0:
            next_node = n
        else:
            next_node = onion_path[n - 1]

        message = bytes(next_node, "utf-8") + encrypted_message
    encrypted_packet = message
    return encrypted_packet

# generate_AES_keys(onion_path)

def decrypt(node, data):
    key = open("keys/{node}.pem".format(node=node)).read()
    cipher = AES.new(key, AES.MODE_CBC)
    decrypted_data = cipher.decrypt(key)
    return decrypted_data


# https://www.pycryptodome.org/en/latest/src/cipher/oaep.html

# Create public and private key PEM files for Nodes 2-7

# def generate_RSA_keys():
#     for n in range(2, 8):

#         key = RSA.generate(2048)  # generate RSA key

#         # PUBLIC KEYS
#         public_key = key.publickey().export_key()  # derive private key from public key
#         file_out = open("public_keys/n{node}.pem".format(node=n), "wb")
#         file_out.write(public_key)
#         file_out.close()

#         # PRIVATE KEY
#         private_key = key.export_key()
#         file_out = open("private_keys/n{node}.pem".format(node=n), "wb")
#         file_out.write(private_key)
#         file_out.close()

#         # print(private_key)
#         # print(public_key)
#     return


# Sender preparing packet to send


# def prepare_onion_packet(onion_path, message):
#     for n in range(len(onion_path) - 1, -1, -1):
#         node = onion_path[n][1]  #'4', '5', '6'

        # key = RSA.importKey(open("public_keys/n{node}.pem".format(node=node)).read())
#         cipher = PKCS1_OAEP.new(
#             key
#         )  # PKCS1_OAEP integrates padding scheme into RSA encryption. Use public key and OAEP to create cipher

#         print("Encrypting with ", onion_path[n], " key....")
#         print("Encrypting Message", message)

#         encrypted_msg = cipher.encrypt(message)  # cnrypt message with cipher
#         if n == 0:
#             next_node = n
#         else:
#             next_node = onion_path[n - 1]

#         message = bytes(next_node, "utf-8") + encrypted_msg

#     encrypted_packet = message
#     return encrypted_packet  # returns 'onion packet'


# def decrypt_packet(message, node):
#     key = RSA.importKey(open('private_keys/n{node}.pem'.format(node=node)).read())
#     cipher = PKCS1_OAEP.new(key) #use oaep and private key to create cipher
#     decrypted_msg = cipher.decrypt(message)
#     print("Decrypted Message", decrypted_msg)
#     return decrypted_msg
