from pwn import *
from Crypto.Cipher import AES

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

ip = "172.26.201.17"

port = 2132 
# Enter 1-5: (note Q5 is worth 2 points)
# $3
# Q3: ECB is bad. Recover the secret.
# You are given an AES-128-ECB Oracle where output=AES-128-ECB-Enc(key,secret||input), where secret is 2 bytes. 
# Enter plaintext in hexstr below. If you are ready to guess the secret, type "c":
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
        # ssss0000000000000000000000000000 1d920000000000000000000000000000     32 byte
        # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc
          
        print(new_text.hex())
        # 2+14+\00\ff+\00\ff+14
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
    data1 = io.recvline().decode("utf-8")
    print(data1)

else:
    print("No matching combination found.")

io.close()

