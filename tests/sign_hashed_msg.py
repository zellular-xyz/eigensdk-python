import unittest
from eigensdk.crypto.bls.attestation import KeyPair, PrivateKey, new_private_key, G1Point

def int2hex(num: int):
	return format(num, '064x')

class TestGlobal(unittest.TestCase):

	def test_case_1(self):
		key = 123456
		key_pair = KeyPair.from_string(f"{key}", 10)

		msg_hash = [1114111867650203226588438438415785729752598011698556980975039687099396486267,20877345556164385361354796096866283186573538440587356036382277190003589615719]
		msg_point = G1Point(msg_hash[0], msg_hash[1])

		sign = key_pair.sign_hashed_to_curve_message(msg_point)

		print("sign: ", sign.getStr())
