from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import binascii
# Q4: Encryption does not provide integrity!!
# You intercept a string plaintext (1 line below), the corresponding (hexstr) AES-128-OFB ciphertext (2 lines below) and (hexstr) IV (3 lines below):
# Gimme 100 Baht
# 609d28e8e35ad7d5a6fb09c0fd08ea78
# 578b9fa3c5c8c994c4056dec0a3e49a0
# Enter a hexstring ciphertext and IV that will be decrypted by the receiver as "Gimme 900 Baht"
   
ip = "172.26.201.17"
port = 2132 

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")

io.sendline(str(4))
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
pt = io.recvline().decode("utf-8")
ciphertext = io.recvline().decode("utf-8")
IV = io.recvline().decode("utf-8")
print(pt)
print(ciphertext)
print(IV)
data1 = io.recvline().decode("utf-8")
print(data1)
pt = bytes(pt.encode("utf-8"))

ciphertext = bytes.fromhex(ciphertext)
IV = bytes.fromhex(IV)
print(ciphertext)
print(IV)

keystream = bytes(x ^ y for x, y in zip(pt, ciphertext))
print("keystream : ",keystream)
new_plaintext = "Gimme 900 Baht"
new_plaintext = bytes(new_plaintext.encode("utf-8"))

new_cipherText = bytes(x ^ y for x, y in zip(keystream, new_plaintext))
print(new_cipherText.hex())
io.sendline(str(new_cipherText.hex()))
io.sendline(str(IV.hex()))

data1 = io.recvline().decode("utf-8")
print(data1)



io.close()

