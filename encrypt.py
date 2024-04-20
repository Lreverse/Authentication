#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import hmac
import binascii
from Crypto.Cipher import AES


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
