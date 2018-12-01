'''
Implementation of 3DES cryptosystem
uses a 168-bit key (3 56-bit keys)
Encrypts 64-bit blocks at a time
'''


initial_perm = [58, 50,	42,	34,	26,	18,	10,	2, 
				60, 52, 44, 36, 28, 20, 12, 4,
				62,	54,	46,	38,	30,	22,	14,	6,
				64,	56,	48,	40,	32,	24,	16,	8,
				57,	49,	41,	33,	25,	17,	9,  1,
				59,	51,	43,	35,	27,	19,	11,	3,
				61,	53,	45,	37,	29,	21,	13,	5,
				63,	55,	47,	39,	31,	23,	15,	7]

final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			  39, 7, 47, 15, 55, 23, 63, 31,
			  38, 6, 46, 14, 54, 22, 62, 30,
			  37, 5, 45, 13, 53, 21, 61, 29,
			  36, 4, 44, 12, 52, 20, 60, 28,
			  35, 3, 43, 11, 51, 19, 59, 27,
			  34, 2, 42, 10, 50, 18, 58, 26,
			  33, 1, 41, 9,  49, 17, 57, 25]

expansion_perm = [32, 1,  2,  3,  4,  5,  4,  5 ,  
				  6,  7,  8,  9,  8,  9,  10, 11, 
				  12, 13, 12, 13, 14, 15, 16, 17,
				  16, 17, 18, 19, 20, 21, 20, 21, 
				  22, 23, 24, 25, 24, 25, 26, 27, 
				  28, 29, 28, 29, 30, 31, 32, 1 ]

straight_perm = [16, 7,  20, 21, 29, 12, 28, 17,
				 1,  15, 23, 26, 5,  18, 31, 10,
				 2,	 8,  24, 14, 32, 27, 3,  9 ,
				 9,	 13, 30, 6,  22, 11, 4,  2 ]

num_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

compression_perm = [14, 17, 11, 24,	1,  5,  3,  28, 
					15, 6,  21, 10, 23, 19, 12, 4 , 
					26, 8,  16, 7,  27, 20, 13, 2 ,
					41, 52, 31, 37, 47, 55, 30, 40,
					51, 45,	33, 48, 44, 49, 39, 56, 
					34, 53, 46, 42, 50, 36, 29, 32]

sboxes = [[[14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7 ],
		   [0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8 ],
		   [4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0 ],
		   [15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13]],

		  [[15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10],
		   [3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5 ],
		   [0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15],
		   [13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9 ]],

		  [[10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8 ],
		   [13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1 ],
		   [13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7 ],
		   [1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12]],

		  [[7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15],
		   [13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9 ],
		   [10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4 ], 
		   [3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14]],

		  [[2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9 ],
		   [14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6 ],
		   [4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14],
		   [11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3 ]],

		  [[12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11],
		   [10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8 ],
		   [9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6 ],
		   [4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13]],

		  [[4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1 ],
		   [13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6 ],
		   [1,  4,  11, 13, 12, 3,  7,  14,	10, 15, 6,  8,  0,  5,  9,  2 ],
		   [6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12]],

		  [[13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7 ],
		   [1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2 ],
		   [7,  11, 4,  1,  9,  12, 14,	2,  0,  6,  10, 13, 15, 3,  5,  8 ],
		   [2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11]]]


# takes a 168-bit key and a message and returns the corrresponding cyphertext
# both parameters should be ints
def encrypt(key, message):

	# parse the 3 keys
	k1 = (key >> 112) & (2**56 - 1)
	k2 = (key >> 56) & (2**56 - 1)
	k3 = key & (2**56 - 1)

	# perform 3DES on the message in blocks of 64-bits
	cyphertext = 0
	i = 0
	while message != 0:
		# get the right most 64-bits and shift
		block = message & (2**64 - 1)
		message = message >> 64

		# encrypt, decrypt, encrypt
		c = des(k3, des(k2, des(k1, block), True))

		# append encrypted block to cyphertext
		cyphertext += c << (64 * i)

		i += 1

	return cyphertext



# takes a 168-bit key and a cyphertext and returns the corrresponding plaintext
# both parameters should be ints
def decrypt(key, cyphertext):

	# parse the 3 keys
	k1 = (key >> 112) & (2**56 - 1)
	k2 = (key >> 56) & (2**56 - 1)
	k3 = key & (2**56 - 1)

	# perform 3DES on the cyphertext in blocks of 64-bits
	plaintext = 0
	i = 0
	while cyphertext != 0:
		# get the right most 64-bits and shift
		block = cyphertext & (2**64 - 1)
		cyphertext = cyphertext >> 64

		# decrypt, encrypt, decrypt
		m = des(k1, des(k2, des(k3, block, True)), True)

		# append decrypted block to plaintext
		plaintext += m << (64 * i)

		i += 1

	return plaintext


# DES encrytion or decryption on an 64-bit block of data
# 56-bit key
# will decrypt if the decrypt flag is set to true
def des(key, block, decrypt=False):

	# generate the keys for all the rounds
	keys = getSubkeys(key)

	#reverse the order if we are decrypting
	if decrypt: keys.reverse()

	#compute initial permutation
	block = permute(block, initial_perm)

	#split the block into 32-bit halves
	left = block >> 32
	right = block & (2**32 - 1)

	#begin the round structure
	for i in range(16):
		temp = right
		right = left ^ round_function(keys[i], right)
		left = temp

	# combine the halves and compute the final permutation (inverse initial)
	combined = left + (right << 32)
	cyphertext = permute(combined, final_perm)

	return cyphertext



# generate a list of 16 48-bit subkeys from a 56-bit key
def getSubkeys(key):

	#initialize empty list for subkeys
	keys = []

	# split key into 28-bit halfs
	left = key >> 28
	right = key & (2**28 - 1)

	# compute 16 rounds of key generating
	for i in range(16):

		# get the amount to shift for this round
		n = num_shifts[i]

		# circular shift left both halves
		left = ((left << n) + (left >> (28-n))) & (2**28 - 1)
		right = ((right << n) + (right >> (28-n))) & (2**28 - 1)

		# combine the halved and compress them into the subkey
		combined = right + (left << 28)
		k = permute(combined, compression_perm)

		keys.append(k)

	return keys




# takes in a 48-bit subkey and 32-bit half block
def round_function(key, bits):

	# expand to 48 bits
	bits = permute(bits, expansion_perm)

	# xor with key
	bits = bits ^ key

	#split into 8 6-bit segments and put through s-boxes
	output = 0
	for i in range(8):
		segment = bits & ((2**8 - 1) << 8*i)
		s = substitute(segment, sboxes[i])
		output += s << (8*i)

	# permute the block
	output = permute(output, straight_perm)

	return output



# permutes the bits according to the permutation table
def permute(bits, permutation):

	output = 0

	# loop through perm table
	for i, p in enumerate(permutation):
		
		# get the p-th bit from bits
		b = (bits >> (p-1)) & 1

		# add this bit to the output
		output += b * 2**i

	return output



# substitute the 6-bit segment according to the sbox
def substitute(bits, sbox):

	# get the x and y values to lookup the sbox
	x = (bits & 1) + ((bits >> 4) & 2)  # outside bits
	y = (bits >> 1) & (2**4 - 1) 		# middle 4 bits

	return sbox[x][y]






