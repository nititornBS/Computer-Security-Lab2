from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
ip = "172.26.201.17"
port = 2132 
# 1: CBC mode of operation. Using Python's pycryptodome AES-CBC (https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode) implementation to encrypt .1MB of zeroes, i.e.:
# data = '\x00'*int(1*10**5)
# data = data.encode()

# Please use 128-bit long zeroed key, use the following IV shown in hexstr below, and answer in hexstr:
# IV: 88cb2a366bda86ad60673e825adfd693

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")

io.sendline(str(1))
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
print(data1)

data1=data1.split()[1]
iv = bytes.fromhex(data1)


# key=bytes(key, 'utf-8')
key = b'\x00' * 16
print(str(key))

data = '\x00'*int(1*10**5)
data = data.encode()

cipher = AES.new(key, AES.MODE_CBC, iv)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
# print(str(ct_bytes))
ct_hexstr = ct_bytes.hex()
# print(ct_hexstr)


io.sendline(ct_hexstr)
flag = io.recvline().decode("utf-8")
print(flag)
io.close()