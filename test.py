from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
# from secp256k1 import PublicKey

import binascii
import codecs

dongle = getDongle(True)

CLA = "80"
INDEX = "01"
P1 = "00"
P2 = INDEX
LEN = "00"
DATA = ""

# Instructions accepted by the Burst Ledger App
INS_GET_VERSION = "01"
INS_AUTH_SIGN_TXN = "03"
INS_ENCRYPT_DECRYPT_MSG = "04"
INS_SHOW_ADDRESS = "05"
INS_GET_PUBLIC_KEY = "06"
INS_SIGN_TOKEN = "07"

INS = INS_GET_VERSION
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("version ", binascii.hexlify(ret))

INS = INS_GET_PUBLIC_KEY
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("publicKey ", binascii.hexlify(ret[1:1+32]))

# Show the address for the given index, blocks for user input (wait for an accept)
# INS = INS_SHOW_ADDRESS
# ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
# print("ret ", str(ret[0]))

# An ordinary payment transaction
INS = INS_AUTH_SIGN_TXN
P1 = "01" # sign init
DATA = "0010b40ad80ae803c980cdc2fded5c1d402fc37eb46eee66706574f037469d47da14f9d7df53f834b6592e05e1c7d3a900e1f505000000008096980000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005191020085834c122c1c5665"
LEN = "b0" # 176
P2 = LEN
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
P1 = "03" # sign finish
P2 = INDEX
DATA = ""
LEN = "00"
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("sig ", binascii.hexlify(ret[1:1+64]))

# Token transfer transaction
INS = INS_AUTH_SIGN_TXN
P1 = "01" # sign init
DATA = "0211223fd80ae80334a7ca8bbded4e3f24c60ecb655f9235ac1b12d97aea698c554df8bf1d950f2db6592e05e1c7d3a900000000000000008096980000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a9102008981c4210120df530151a4f5468b89f5faa00f000000000000"
LEN = "c1" # 193
P2 = LEN
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
P1 = "03" # sign finish
P2 = INDEX
DATA = ""
LEN = "00"
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("sig ", binascii.hexlify(ret[1:1+64]))


# Token transfer transaction (TRT)
INS = INS_AUTH_SIGN_TXN
P1 = "01" # sign init
DATA = "0211e405d90aa005416d25901e5b4f8e03d00c92fd508798d3794883e4a73630ab9e88454b7aed49d84228d09c9f7e2d0000000000000000b0dfc90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009a7b0b0025241b746d4b92e2018409fe8f2e3b1eace803000000000000"
LEN = "c1" # 193
P2 = LEN
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
P1 = "03" # sign finish
P2 = INDEX
DATA = ""
LEN = "00"
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("sig ", binascii.hexlify(ret[1:1+64]))

# Token buy offer (TRT)
INS = INS_AUTH_SIGN_TXN
P1 = "01" # sign init
DATA = "02130609d90aa005416d25901e5b4f8e03d00c92fd508798d3794883e4a73630ab9e88454b7aed4900000000000000000000000000000000209586000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a27b0b00add44456cab796a4018409fe8f2e3b1eac50c3000000000000c409000000000000"
LEN = "c9" # 201
P2 = LEN
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
P1 = "03" # sign finish
P2 = INDEX
DATA = ""
LEN = "00"
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("sig ", binascii.hexlify(ret[1:1+64]))

# Token cancel offer
INS = INS_AUTH_SIGN_TXN
P1 = "01" # sign init
DATA = "0215840cd90aa005416d25901e5b4f8e03d00c92fd508798d3794883e4a73630ab9e88454b7aed4900000000000000000000000000000000209586000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a47b0b0065491ec2c52052c7019567ff4148b62b98"
LEN = "b9" # 185
P2 = LEN
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
P1 = "03" # sign finish
P2 = INDEX
DATA = ""
LEN = "00"
ret = dongle.exchange(bytearray.fromhex(CLA + INS + P1 + P2 + LEN + DATA))
print("ret ", str(ret[0]))
print("sig ", binascii.hexlify(ret[1:1+64]))