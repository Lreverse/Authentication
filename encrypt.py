#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import hmac
import binascii
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def hash_md5(username: bytes, pwd: bytes):
    """md5散列"""
    hash_obj = hashlib.md5()
    hash_obj.update(username + pwd)
    return hash_obj.hexdigest()


def hash_salt(key: bytes, msg: bytes):
    """sha256加密，盐为密钥"""
    hmac_object = hmac.new(key, msg, digestmod=hashlib.sha256)
    return hmac_object.hexdigest()


def AES_Encode(key: bytes, plaintext: bytes):
    """AES加密，密钥和明文必须是16字节的倍数"""
    aes = AES.new(key, AES.MODE_ECB)
    ciphertext = aes.encrypt(plaintext)
    return binascii.hexlify(ciphertext).decode()


def AES_Decode(key: bytes, ciphertext: bytes):
    """AES解密, 参数为字节类型"""
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext)
    return binascii.hexlify(plaintext).decode()


def rsa_generate_key():
    """生成rsa密钥对"""
    key = RSA.generate(2048)
    with open('private.pem', 'wb') as f:
        f.write(key.exportKey())
    with open('public.pem', 'wb') as f:
        f.write(key.public_key().exportKey())


def rsa_encode(plaintext: bytes, key_path: str):
    key = RSA.importKey(open(key_path).read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return binascii.hexlify(ciphertext).decode()


def rsa_decode(ciphertext: bytes, key_path: str):
    key = RSA.importKey(open(key_path).read())
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()
