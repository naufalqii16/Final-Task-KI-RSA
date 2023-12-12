import random
import math
import socket

# =============================== DES ==============================================
def hex2bin(s):
	mp = {'0': "0000",'1': "0001",'2': "0010",'3': "0011",'4': "0100",'5': "0101",'6': "0110",'7': "0111",'8': "1000",'9': "1001",'A': "1010",'B': "1011",'C': "1100",'D': "1101",'E': "1110",'F': "1111"}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin


# Fungsi untuk mengkonversi dari binary ke hexadecimal

def bin2hex(s):
	mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3', "0100": '4', "0101": '5', "0110": '6', "0111": '7', "1000": '8', "1001": '9', "1010": 'A', "1011": 'B', "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
	hex = ""
	for i in range(0, len(s), 4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]

	return hex


# Fungsi untuk mengkonversi dari binary ke decimal

def bin2dec(binary):

	decimal, i = 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal


# Fungsi untuk mengkonversi dari decimal ke binary

def dec2bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res


# fungsi untuk melakukan permutation

def permute(k, arr, n): 	#contoh pt = permute(pt, initial_perm, 64)
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation


# fungsi untuk melakukan shift left

def shift_left(k, nth_shifts): 	# contoh : left = shift_left(left, shift_table[i])
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k


# fungsi untuk melakukan operasi xor antara dua nilai biner dari string a dan b

def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans


# Tabel angka yang digunakan dalam proses initial permutation
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

# Tabel angka yang digunakan untuk Expansion D-box Table = mengekspansi dari 32 bit menjadi 48 bits agar dapat di xor dengan round key
# ada yang diduplikat buat ekspansinya, seperti 4, 5, 8, 9, dll
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

# Permutation Table (Transposition P-Box)
per = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Tabel angka untuk mengoperasikan final permutation yang akan mengoutputkan chiper text
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]


def encrypt(pt, rkb, rk):
	pt = hex2bin(pt)

	# Initial Permutation
	pt = permute(pt, initial_perm, 64)
	# print("After initial permutation", bin2hex(pt))
	# print("| Round     |  left      |  Right     |  round key ")

	# Splitting
	left = pt[0:32]
	right = pt[32:64]
	for i in range(1, 17):
		# Expansion D-box: Expanding the 32 bits data into 48 bits
		right_expanded = permute(right, exp_d, 48)

		# XOR RoundKey[i] and right_expanded
		xor_x = xor(right_expanded, rkb[i-1])

		# S-boxex: substituting the value from s-box table by calculating row and column
		sbox_str = ""
		for j in range(0, 8): # 100101
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5])) #mengambil index row di tabel sbox lewat angka ke "[0]"+"[5]"
			col = bin2dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec2bin(val)

		# Straight D-box: After substituting rearranging the bits
		# Transposition P-Box
		sbox_str = permute(sbox_str, per, 32) 

		# XOR left and sbox_str
		result = xor(left, sbox_str)
		left = result

		# Swapper
		if(i != 16):
			left, right = right, left
		# print("| Round ", i, " | ", bin2hex(left),
		# 	" | ", bin2hex(right), " | ", rk[i-1])

	# Combination
	combine = left + right

	# Final permutation: final rearranging of bits to get cipher text
	cipher_text = permute(combine, final_perm, 64)
	return cipher_text

def key_exchange_client(keys, text, type):
    
    # Key generation
    # --hex to binary
    key = hex2bin(keys)

    # Tabel angka yang digunakan untuk menjadikan 64 bit initial key menjadi 56 bit efektif key
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # proses mendrop bit-bit tertentu agar bisa dari 64 menjadi 56 bit
    key = permute(key, keyp, 56)

    # Tabel yang berisi angka-angka yang dipakai untuk melakukan shift table
    # setiap bit ke 1, 2, 9, 16 geser 1 posisi
    shift_table = [1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1]

    # Key- Compression Table : mengkompres dari 56 bit menjadi 48 bit
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    # Splitting
    left = key[0:28] 
    right = key[28:56] 

    rkb = [] # rkb for RoundKeys in binary
    rk = [] # rk for RoundKeys in hexadecimal

    # looping untuk mengenerate round key
    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # mengkombinasikan hasil splitting kiri dan kanan untuk dikompress menjadi 48 bit
        combine_str = left + right

        # Proses kompress key dari 56 bit menjadi 48 bit round key menggunakan permuted
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    # =========================================
    
      # Ganti dengan plaintext yang diinginkan
    if type == "encrypt":
        try:		
            cipher_text = bin2hex(encrypt(text, rkb, rk))
            return cipher_text
        except:
            print("text harus hexa")
    elif type == "decrypt":
        rkb_rev = rkb[::-1]
        rk_rev = rk[::-1]
        try:
            decrypted_text = bin2hex(encrypt(text, rkb_rev, rk_rev))
            return decrypted_text
        except:
            print("text harus hexa")
        
    
	

    # chipertext_h1 = client_socket.recv(1024).decode()
    # print(f"chipertext yang diterima dari h1: {chipertext_h1}")

    # Proses dekripsi ciphertext menggunakan DES (gunakan implementasi DES yang telah Anda buat sebelumnya)
    

# =============================== END DES ==============================================

def is_prime(number):
    if number < 2:
        return False
    for i in range(2, number // 2+1):
        if number % i == 0:
            return False
    return True

def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime

def mod_inverse(e, phi):
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    return ValueError('No mod inverse found')

def encrypt_rsa(msg, e, n):
    msg_encoded = [ord(c) for c in msg]
    # (m^e) mod n = chipertext
    # pow(c, e, n) = c^e mod n
    chipertext = [pow(c, e, n) for c in msg_encoded]
    return chipertext

def decrypt_rsa(chipertext, d, n):
    # decryption
	msg_encoded = [pow(ch, d, n) for ch in chipertext]
	msg = ''.join([chr(c) for c in msg_encoded])
	return msg


p, q = generate_prime(100, 1000), generate_prime(100, 1000)

while p == q:
    q = generate_prime(100, 1000)

n = p * q

phi_n = (p - 1) * (q - 1)

e = random.randint(3, phi_n-1)

while math.gcd(e, phi_n) != 1:
    e = random.randint(3, phi_n-1)


d = mod_inverse(e, phi_n)

id_alice = "a001"
id_bob = "b001"
Na = "123456"

pair_1 = Na + id_alice

print("public key: ", e)
print("private key: ", d)

key_alice = "AABB09182736CCDD"

# =============================== CONNECT TO BOB USING SOCKET ==============================================
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
port = 12345
server_socket.bind((host, port))
server_socket.listen()

print(f"Server berjalan di {host}:{port}")

client_socket, addr = server_socket.accept()
print(f"Menerima koneksi dari {addr}")


# ============================================================================================================
# ============================ RECEIVE AND SEND PUBLIC KEY WITH n VALUES =====================================

# Send the n_bytes through the socket
client_socket.send(str(e).encode())
client_socket.send(str(n).encode())


# RECEIVE PUBLIC KEY & n FROM BOB =============================

# Receive data from the client
e_bob = client_socket.recv(1024).decode()
e_bob = int(e_bob)

# Receive data from the client
n_bob = client_socket.recv(1024).decode()
n_bob = int(n_bob)

# =========================================  STEP 1 - TO BOB   =============================================================

send_1 = encrypt_rsa(pair_1, e_bob, n_bob)
send_1 = str(send_1)
client_socket.send(send_1.encode())

# =========================================  STEP 2 - TO BOB   =============================================================
pair_2 = client_socket.recv(1024).decode()
pair_2 = eval(pair_2)
print("ini pair step 2 dari bob: ", pair_2)
Nb = pair_2[:6]
print("Nb: ", Nb)
Na_from_bob = ''.join(pair_2[6:])

print("Na_from_bob: ", Na_from_bob)
print("Na: ", Na)
# validate Na
if Na_from_bob == Na:
    print("Na is valid")
    Nb = decrypt_rsa(Nb, d, n)

    # =========================================  STEP 3 - TO BOB   =============================================================
    Nb_encrypted = encrypt_rsa(Nb, e_bob, n_bob)
    Nb_encrypted = str(Nb_encrypted)
    client_socket.send(Nb_encrypted.encode())
    # =========================================  STEP 4 - TO BOB   =============================================================
    print("Let's Talks with bob")
    client_socket.send(key_alice.encode())
    plaintext = "12345678AABBCDEE"
    type = "encrypt"
    chipertext = key_exchange_client(key_alice, plaintext, type)
    print("plaintext for bob: ", plaintext)
    print("chipertext for bob: ", chipertext)
    client_socket.send(chipertext.encode())

else:
    print("Na is not valid, youre not Bob")
    client_socket.close()


# =============================================================================
# ============================================================================================================
# =========================================  STEP 1 - FROM BOB   =============================================================
print("=========== Receive from Bob ===========")
Nb = client_socket.recv(1024).decode()
Nb = eval(Nb)
id_b = Nb[6:]
Nb = Nb[:6]

Nb = decrypt_rsa(Nb, d, n)

Na_encrypted = encrypt_rsa(Na, e_bob, n_bob)
print("Na_encrypted: ", Na_encrypted)
# Na_encrypted = str(Na_encrypted)

# =========================================  STEP 2 - FROM BOB   =============================================================
pair_2 = Na_encrypted + [Nb]
print("pair_2: ", pair_2)
pair_2 = str(pair_2)

client_socket.send(pair_2.encode())

# =========================================  STEP 3 - FROM BOB   =============================================================
Na_from_bob = client_socket.recv(1024).decode()
Na_from_bob = eval(Na_from_bob)

Na_from_bob = decrypt_rsa(Na_from_bob, d, n)

if Na_from_bob == Na:
    print("Na is valid")
    # =========================================  STEP 4 - FROM BOB   =============================================================
    print("Let's Talks with Bob")
    key_bob = client_socket.recv(1024).decode()
	
    # receive chipertext
    chipertext_from_bob = client_socket.recv(1024).decode()
    print("chipertext from bob: ", chipertext_from_bob)
    type = "decrypt"
    plaintext = key_exchange_client(key_bob, chipertext_from_bob, type)
    print("plaintext from bob: ", plaintext)
	
else:
    print("Na is not valid, youre not Alice")
    client_socket.close()




