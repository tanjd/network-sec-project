from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pathlib import Path


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


def generate_AES_keys(path):
    for node in path:
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        public_dir = Path("keys")
        public_dir.mkdir(exist_ok=True)
        file_out = open("keys/{node}.bin".format(node=node), "wb")
        file_out.write(key + iv)
        # file_out.write(iv)
        file_out.close()
    return


def prepare_onion_packet(path, message):

    for n in range(len(path) - 1, -1, -1):
        key_file = open("keys/{node}.bin".format(node=path[n]), "rb").read()
        key = key_file[0:16]
        iv = key_file[16:]
        # print('current msg: ', message, ' length ', len(message))
        print("\nEncrypting with {n} key ...".format(n=path[n]))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(pad(message, AES.block_size))
        print(
            "encrypted message", encrypted_message, " length ", len(encrypted_message)
        )

        if n != 0:
            next_node = path[n - 1]
            message = bytes(next_node, "utf-8") + encrypted_message
        else:
            message = encrypted_message
        # print('next message to encrypt', message)
    encrypted_packet = message
    return encrypted_packet


def AES_decrypt(data, node):
    key_file = open("keys/{node}.bin".format(node=node), "rb").read()
    key = key_file[0:16]
    iv = key_file[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    unpadded = unpad(decrypted, AES.block_size)
    return (unpadded[0:2], unpadded[2:])  # Returns (Next Addr, Msg)


path = ["N4", "N5", "N6"]
message = b"N3Hello"
# generate_AES_keys(path)
packet = prepare_onion_packet(path, message)

# print('\nFinal Packet ', packet)
# print('Number of bytes', len(packet))
next_addr, decrypted_data = AES_decrypt(packet, "N4")

print(next_addr, decrypted_data, "length of decrypted data", len(decrypted_data))

next_addr, decrypted_data = AES_decrypt(decrypted_data, "N5")
print(next_addr, decrypted_data, "length of decrypted data", len(decrypted_data))

next_addr, decrypted_data = AES_decrypt(decrypted_data, "N6")

print(next_addr, decrypted_data, "length of decrypted data", len(decrypted_data))


# https://www.pycryptodome.org/en/latest/src/cipher/oaep.html

# Create public and private key PEM files for Nodes 2-7

# def generate_RSA_keys(path):
#     for node in path:

#         key = RSA.generate(2048)  # generate RSA key

#         public_dir = Path('public_keys')
#         public_dir.mkdir(exist_ok=True)

#         private_dir = Path('private_keys')
#         private_dir.mkdir(exist_ok=True)

#         # PUBLIC KEYS
#         public_key = key.publickey().export_key()
#         file_out = open("public_keys/{node}.pem".format(node=node), "wb")
#         file_out.write(public_key)
#         file_out.close()

#         # PRIVATE KEY
#         private_key = key.export_key()
#         file_out = open("private_keys/{node}.pem".format(node=node), "wb")
#         file_out.write(private_key)
#         file_out.close()

#         # print(private_key)
#         # print(public_key)
#     return

# # Sender preparing packet to send


# def prepare_onion_packet(path, message):
#     for n in range(len(path) - 1, -1, -1):
#         node = path[n][1]  #'4', '5', '6'

#         key = RSA.importKey(open("public_keys/{node}.pem".format(node=path[n])).read())
#         cipher = PKCS1_OAEP.new(
#             key
#         )  # PKCS1_OAEP integrates padding scheme into RSA encryption. Use public key and OAEP to create cipher

#         print("Encrypting with ", path[n], " key....")
#         print("Encrypting Message", message)

#         encrypted_msg = cipher.encrypt(message)  # cnrypt message with cipher
#         if n == 0:
#             next_node = n
#         else:
#             next_node = path[n - 1]

#         message = bytes(next_node, "utf-8") + encrypted_msg

#     encrypted_packet = message
#     return encrypted_packet  # returns 'onion packet'


# def RSA_decryption(message, node):
#     key = RSA.importKey(open('private_keys/{node}.pem'.format(node=node)).read())
#     cipher = PKCS1_OAEP.new(key) #use oaep and private key to create cipher
#     decrypted_msg = cipher.decrypt(message)
#     print("Decrypted RSA: ", decrypted_msg)
#     return decrypted_msg


# generate_RSA_keys(path)
# prepare_onion_packet(path, b'N3Hello')
# key_file = open("keys/N6.bin", "rb").read()
# key = key_file[0:16]
# iv = key_file[16:]

# cipher = AES.new(key, AES.MODE_CBC, iv)

# encrypted_message = cipher.encrypt(pad(b'N3Hello', AES.block_size))
# print("encrypted message", encrypted_message)
# key = RSA.importKey(open("public_keys/N6.pem").read())
# cipher = PKCS1_OAEP.new(
#             key
#         )
# encrypted_message = cipher.encrypt(encrypted_message)
# print(encrypted_message)
# print('Length of text after N6 encryptions:', len(encrypted_message), type(encrypted_message))

# key_file = open("keys/N5.bin", "rb").read()
# key = key_file[0:16]
# iv = key_file[16:]

# cipher = AES.new(key, AES.MODE_CBC, iv)

# encrypted_message = cipher.encrypt(pad(encrypted_message, AES.block_size))
# print(encrypted_message, len(encrypted_message))
# key = RSA.importKey(open("public_keys/N5.pem").read())
# cipher = PKCS1_OAEP.new(
#             key
#         )
# encrypted_message = cipher.encrypt(encrypted_message)
# print(encrypted_message)
# print('Length of text after N5 encryptions:', len(encrypted_message), type(encrypted_message))
# # encrypted_msg = RSA_decryption(ciphertext, 'N6')
# # print('Final decrypted msg', AES_decrypt(encrypted_msg, 'N6'))
