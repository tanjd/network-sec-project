# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
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


def generate_AES_keys(onion_path):
    for node in onion_path:
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        file_out = open("keys/{node}.bin".format(node=node), "wb")
        file_out.write(key+iv)
        # file_out.write(iv)
        file_out.close()
    return


def decrypt(node, data):
    key_file = open("keys/{node}.bin".format(node=node), "rb").read()
    key = key_file[0:16]
    iv = key_file[16:]
    

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data


def prepare_onion_packet(onion_path, message):

    for n in range(len(onion_path) - 1, -1, -1):
        key_file = open("keys/{node}.bin".format(node=onion_path[n]), "rb").read()
        key = key_file[0:16]
        iv = key_file[16:]

        print("\nEncrypting with {n} key ...".format(n=onion_path[n]))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(pad(message, AES.block_size))
        print("encrypted message", encrypted_message)

        if n == 0:
            next_node = onion_path[n]
        else:
            next_node = onion_path[n - 1]
        message = bytes(next_node, "utf-8") + encrypted_message

        print('next message to encrypt', message)
    encrypted_packet = message
    return encrypted_packet


# generate_AES_keys(onion_path)
encrypted_onion_packet = prepare_onion_packet(onion_path, b'N3hello')
print('\nFinal Packet ', encrypted_onion_packet)
print('Number of bytes', len(encrypted_onion_packet))




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
