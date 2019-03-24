#coding=utf-8
__author__ = 'zxlee'
import json
import base64
import re
import hashlib
from Crypto.Cipher import AES
pwd_aes_key = '6d3121b650e42855'
def get_sign(interface,data,timestamp):
	key_value_str = ''
	for key,value in sorted(data.items()):
		key_value_str = key_value_str + str(key) + str(value)
	final_str = '262b6c001ea05beceb9d560be1dbf14f' + interface + key_value_str + timestamp	+ ' 262b6c001ea05beceb9d560be1dbf14f'
	return md5_encryt(final_str)

def get_enc_pwd(pwd):
	return aes_encryt(pwd,pwd_aes_key).strip()

def md5_encryt(str):
	md = hashlib.md5()
	md.update(str.encode())
	return md.hexdigest()

def aes_encryt(str, key):
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    cipher = AES.new(key, AES.MODE_ECB,str)
    msg = cipher.encrypt(pad(str))
    msg = base64.encodestring(msg)
    return msg

def aes_decrypt(enStr, key):
    unpad = lambda s: s[0:-ord(s[-1])]
    cipher = AES.new(key, AES.MODE_ECB)
    decryptByts = base64.decodestring(enStr)
    msg = cipher.decrypt(decryptByts)
    msg=unpad(msg)
    return msg