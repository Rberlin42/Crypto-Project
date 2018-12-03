'''
SHA-1 imlementation
'''

import math

# Hash a message using SHA-1 algorithm
# returns a hash of 160-bits
# m is an int
def hash(m):

	# get bit length
	l = m.bit_length()

	# add padding to m
	m = (m << 1) + 1
	padding = (512 - (l + 1)) % 512
	m = m << padding
	m = m | l

	#initialize hash
	h0 = int("0x67452301", 16)
	h1 = int("0xEFCDAB89", 16)
	h2 = int("0x98BADCFE", 16)
	h3 = int("0x10325476", 16)
	h4 = int("0xC3D2E1F0", 16)

	# hash in chunks of 512 bits
	for _ in range(m.bit_length() // 512):

		# break the chunk into 32-bit words
		w = []
		for _ in range(16):
			word = m & (2**32 - 1)
			w.append(word)
			m = m >> 32

		# extend to 80 words
		for i in range(16, 80):
			word = circularShift(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 32, 1)
			w.append(word)

		# initailize values for this chunk
		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		# main computation loop
		for i in range(80):

			if i < 20:
				f = (b & c) | ((~ b) & d)
				k = int("0x5A827999", 16)
			elif i < 40:
				f = b ^ c ^ d
				k = int("0x6ED9EBA1", 16)
			elif i < 60:
				f = (b & c) | (b & d) | (c & d)
				k = int("0x8F1BBCDC", 16)
			else:
				f = b ^ c ^ d
				k = int("0xCA62C1D6", 16)

			temp = (circularShift(a, 64, 5) + f + e + k + w[i]) & (2**32 -1)
			#print(temp)
			e = d
			d = c
			c = circularShift(b, 64, 30)
			b = a
			a = temp

	    # add this chunk to total
	    # make sure we are still 32 bits
		h0 = (h0 + a) & (2**32 -1)
		h1 = (h1 + b) & (2**32 -1)
		h2 = (h2 + c) & (2**32 -1)
		h3 = (h3 + d) & (2**32 -1)
		h4 = (h4 + e) & (2**32 -1)

	# Compute final hash result
	H = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

	return H

# perform a left circular shift on num by n number of bits
# len is the number of bits in num
def circularShift(num, len, n):
	return ((num << n) + (num >> (len-n))) & (2**len - 1)

