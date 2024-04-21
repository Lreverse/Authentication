#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tcp import *
import packet
import json
import encrypt
import binascii
import pymysql
import datetime

SERVER_IP = "127.0.0.1"
PORT = 8888
BUFFER_SIZE = 2048
server = None

db = pymysql.connect(
    host='localhost',
    user='root',
    password='0011223',
    database='db_authentication'
)


def deal_data(data):
    """根据包格式调用对应的处理函数"""
    rq = json.loads(data)  # 先反序列化
    pack_type = rq["type"]
    match pack_type:
        case packet.EXIT_RQ:
            return False
        case packet.LOGIN_RQ:
            login_handle(rq)
        case packet.REGISTER_RQ:
            register_handle(rq)
        case packet.CHANGE_PWD_RQ:
            change_pwd_handle(rq)
        case _:
            pass
    return True


def login_handle(data):
    """处理登录请求"""
    print(">  login_rq", data)
    username = data["username"]
    hash2 = data["hashcode"]
    mac = data["MAC"]

    # 查询sql查找对应关系
    cursor = db.cursor()
    sql = f"select * from users where username = '{username}'"  # 查询
    try:
        cursor.execute(sql)
        result = cursor.fetchall()
    except Exception as e:
        print(f">  error: {e}")

    if not result:
        rs = packet.login_rs_error("user not exit")
    else:
        server.username = result[0][1]
        server.hash1 = result[0][2]
        hash2_ver = encrypt.hash_salt(server.hash1.encode(), mac.encode())

        # 验证hash2，防止消息被篡改
        if hash2 == hash2_ver:
            # 验证成功，返回AES(hash1, 认证码)
            hash1_byte = binascii.unhexlify(server.hash1.encode())  # 将hash1转为字节流
            mac_byte = binascii.unhexlify(mac.encode())  # 将16进制的mac转换为字节流
            cipher = encrypt.AES_Encode(hash1_byte, mac_byte)  # AES加密mac，密钥为hash1
            rs = packet.login_rs_success(cipher)
        else:
            # 验证失败，返回error信息
            rs = packet.login_rs_error("authentication failure")
    response_data = json.dumps(rs)
    server.send(response_data)


def register_handle(data):
    pass


def change_pwd_handle(data):
    """处理修改密码请求"""
    print(">  change_pwd_rq", data)
    new_cipher = data["new_cipher"]
    new_hash2 = data["new_hash2"]
    new_hash2_ver = encrypt.hash_salt(server.hash1.encode(), new_cipher.encode())

    # 验证new_hash2，防止消息被篡改
    if new_hash2 == new_hash2_ver:
        # 验证成功，则使用hash1解密new_cipher，然后更新数据库
        key_byte = binascii.unhexlify(server.hash1.encode())
        new_cipher_byte = binascii.unhexlify(new_cipher.encode())
        new_hash1 = encrypt.AES_Decode(key_byte, new_cipher_byte)

        cursor = db.cursor()
        sql = f"update users set password = '{new_hash1}' where username = '{server.username}'"
        try:
            cursor.execute(sql)
            db.commit()
            rs = packet.change_pwd_rs_success()
        except Exception as e:
            db.rollback()
            print(f">  error: {e}")
            rs = packet.change_pwd_rs_error(e)
    else:
        rs = packet.change_pwd_rs_error("authentication failure")
    response_data = json.dumps(rs)
    server.send(response_data)


if __name__ == '__main__':
    server = tcpServer(SERVER_IP, PORT, BUFFER_SIZE)
    server.bind()
    server.listen()
    while True:
        server.accept()
        server.send("Welcome to Lyp's server")
        while True:
            recv_data = server.recv()
            flag = deal_data(recv_data)
            if not flag:
                server.accept_close()
                break
