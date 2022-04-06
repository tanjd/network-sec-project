from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#or pip install pycryptodome

N4_PORT = 8400
N4_routing= {
    "2a": "N2", #entry
    "5a": "N5", 
}

N5_PORT = 8500
N5_routing= {
    "4a": "N4",
    "6a": "N6",
}

N6_PORT = 8600
N6_routing= {
    "5a": "N5",
    "7a": "N7",
}

N7_PORT = 8700
N7_routing= {
    "3a": "N3", #exit
    "6a": "N6",
}


#https://www.pycryptodome.org/en/latest/src/cipher/oaep.html


message=b"N3N2N3\x16\x2a\x3a\x01\x07hello"
secret_code = "onionethernetN6key"
key = RSA.generate(2048) #generate RSA key
private_key = key.export_key()
public_key = key.publickey().export_key() #derive private key from public key

print(private_key)
print(public_key)

#write public key to file
file_out = open("public.pem", "wb")
file_out.write(public_key)
file_out.close()

#write private key to file
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

#PKCS1_OAEP integrates padding scheme into RSA encryption
#Use public key and OAEP to create cipher
key = RSA.importKey(open('public.pem').read())
cipher = PKCS1_OAEP.new(key)
encrypted_msg = cipher.encrypt(message) #cnrypt message with cipher
print("Encrypted Message", encrypted_msg)

key = RSA.importKey(open('private.pem').read())
cipher = PKCS1_OAEP.new(key) #use oaep and private key to create cipher
decrypted_msg = cipher.decrypt(encrypted_msg)
print("Decrypted Message", decrypted_msg)

