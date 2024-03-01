from base64 import b64decode
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# Enter 1-5: (note Q5 is worth 2 points)
# $2
# Q2: Avoid reusing counter in CTR. You should never repeat the counter (nonce+monotonic counter) in CTR mode! 2 ciphertexts encrypted using AES-128 in CTR mode are given below (in hex string):
# 16d96b70388aec83c6398a1754f3ef40a54fdf735d63fa1d3223f8064fe9b9cd
# 17d86a71398bed82c7388b1655f2ee41a44ede725c62fb1c3322f9074ee8b8cc
# Oops the first plaintext is leaked below:
# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Recover the second plaintext!
ip = "172.26.201.17"
port = 2132 

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")

io.sendline(str(2))
data1 = io.recvline().decode("utf-8")
cipher_text1 = io.recvline().decode("utf-8")
cipher_text2= io.recvline().decode("utf-8")
temp= io.recvline().decode("utf-8")
temp= io.recvline().decode("utf-8")
temp= io.recvline().decode("utf-8")
print(cipher_text1)
print(cipher_text2)

cipher_text1 = bytes.fromhex(cipher_text1)
cipher_text2 = bytes.fromhex(cipher_text2)

leaked_plaintext_hex = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
leaked_plaintext = leaked_plaintext_hex.encode('utf-8')

keystream = bytes(x ^ y for x, y in zip(leaked_plaintext, cipher_text1))
# \00\22\33
# \44\55\66
# [\00,\44],[\22,\55]
print(keystream)
recovered_plaintext = bytes(x ^ y for x, y in zip(cipher_text2, keystream))
print(recovered_plaintext.decode())
io.sendline(recovered_plaintext)

# print(flag)
temp= io.recvline().decode("utf-8")
print(temp)

io.close()