from pwn import *
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad

# Q5: 2DES=DES. Heres the flag encrypted using 2DES. Each key is 6-random digits padded to DES key size (see generate_key())
# c04919721641f84ab6de698810a8f53ec7c66dbed881ff5a2bf34be096aad8df7d96d16f7f1480b12e73486860d3855b
# Heres a ciphertext for "Good luck!" encrypted using the same algorithm and the same keys
# 25ec2e4268d77aefaab544c1e0c4ee98

ip = "172.26.201.17"
port = 2132 

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


key1_index=0
key2_index=0

# DIGIT = '0123456789'
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
    #p -> E(key1) -> x ->E(k2) ->c
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

else:
    print("No match found.")


io.close()
