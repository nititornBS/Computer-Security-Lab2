from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import DES
flag1 =""
flag2 =""
flag3 =""
flag4 =""
flag5 =""

# _________________________________         Q1          _________________________________
ip = "172.26.201.17"
port = 2132 

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

key = b'\x00' * 16
print(str(key))

data = '\x00'*int(1*10**5)
data = data.encode()

cipher = AES.new(key, AES.MODE_CBC, iv)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

ct_hexstr = ct_bytes.hex()

io.sendline(ct_hexstr)
flag1 = io.recvline().decode("utf-8")
print(flag1)


# _________________________________         Q2          _________________________________


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
print(keystream)
recovered_plaintext = bytes(x ^ y for x, y in zip(cipher_text2, keystream))
print(recovered_plaintext.decode())
io.sendline(recovered_plaintext)

flag2= io.recvline().decode("utf-8")
print(temp)


# _________________________________         Q3          _________________________________

def check_ciphertext_equal(ciphertext1):
    ciphertext1=ciphertext1[1:]
    part_length = len(ciphertext1) // 3
    part_half1 = ciphertext1[:part_length]
    part_half2 = ciphertext1[part_length:part_length+part_length]
    part_half3 = ciphertext1[part_length+part_length::]
    print(part_half1)
    print(part_half2)
    print(part_half3)


    return part_half1 == part_half2 

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")

io.sendline(str(3))
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
temp_text = b'\00'*14 #14 bytes 
print(temp_text)
io.sendline(temp_text.hex())
ciphertext_main = io.recvline().decode("utf-8")
print(ciphertext_main)


byte_value1_str ='00'
byte_value2_str ='00'

found_combination = False
for value1 in range(256): #00 01 02 --> ff
    byte_value1 = format(value1, '02X') #0 -> 00 5->05 a-f
    for value2 in range(256):
        byte_value2 = format(value2, '02X')
        byte_value1_str = byte_value1   # 00
        byte_value2_str = byte_value2   #  01
        new_text = temp_text + bytes.fromhex(byte_value1_str) +bytes.fromhex(byte_value2_str) +temp_text
        print(new_text.hex())
        io.sendline(new_text.hex())
        cipher_text = io.recvline().decode("utf-8")

        if check_ciphertext_equal(cipher_text):
            found_combination = True
            break

    if found_combination:
        break

if found_combination:
    print("Yes, you did it!")
    print("Byte 1:", byte_value1_str)
    print("Byte 2:", byte_value2_str)

    io.sendline("c")
    data1 = io.recvline().decode("utf-8")
    text1 = byte_value1_str + byte_value2_str
    text1 = bytes.fromhex(text1)
    print(text1.hex())
    io.sendline(text1.hex())
    flag3 = io.recvline().decode("utf-8")
    print(flag3)

else:
    print("No matching combination found.")


# _________________________________         Q4          _________________________________
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

flag4 = io.recvline().decode("utf-8")
print(flag4)


# _________________________________         Q5          _________________________________

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
io.sendline(str(5))
data1 = io.recvline().decode("utf-8")
print(data1)

flag_CT = io.recvline().decode("utf-8")
print(flag_CT)

pt = io.recvline().decode("utf-8")
pt = pt.split('"')[1]
print(pt)

ct_GL = io.recvline().decode("utf-8")
print(ct_GL)

encrypted_text = []
decrypted_text = []
key_set = []


# DIGIT = '0123456789'
key1_index=0
key2_index=0
# key = 6 random digits padded to DES key size (64 bits or 8 bytes)

# random_digits = ''.join(random.choice(DIGIT) for _ in range(6))
# random_digits = str.encode(random_digits)
# print(pad(random_digits, 8))


pt_padded = pad(str.encode(pt), DES.block_size)
ct_hex = bytes.fromhex(ct_GL)
FlagCT_hex = bytes.fromhex(flag_CT)
for i in range(1000000):
    N = format(i, '06')
    # 1 = 000001
    
    N = str.encode(N)
    key = pad(N, 8)
    print(key)
    
    key_set.append(key)
    cipher1 = DES.new(key, DES.MODE_ECB)

    en_msg = cipher1.encrypt(pt_padded)
    encrypted_text.append(en_msg)

    de_msg = cipher1.decrypt(ct_hex)
    decrypted_text.append(de_msg)

encrypted_set = set(encrypted_text)
decrypted_set = set(decrypted_text)

common_elements = encrypted_set.intersection(decrypted_set)

key1_index = None
key2_index = None

if common_elements:
    print("Match found! Common elements:", common_elements)
    for common_element in common_elements:
        for i in range(len(key_set)):
            if encrypted_text[i] == common_element:
                key1_index = i
            if decrypted_text[i] == common_element:
                key2_index = i
            if key1_index is not None and key2_index is not None:
                break
        if key1_index is not None and key2_index is not None:
            break

    if key1_index is not None and key2_index is not None:
        print("key 1 ", key_set[key1_index], " key 2 ", key_set[key2_index])
        cipher2 = DES.new(key_set[key2_index], DES.MODE_ECB)
        de_msg = cipher2.decrypt(FlagCT_hex)


        cipher2 = DES.new(key_set[key1_index], DES.MODE_ECB)
        de_msg2 = cipher2.decrypt(de_msg)
        decoded_string = unpad(de_msg2, DES.block_size).decode('latin-1')
        print(de_msg2.hex())
        print(decoded_string)
        flag5=decoded_string

else:
    print("No match found.")

print("this is all Flag that i got ")
print("flag 1 : ",flag1)
print("flag 2 : ",flag2)
print("flag 3 : ",flag3)
print("flag 4 : ",flag4)
print("flag 5 : ",flag5)

io.close()