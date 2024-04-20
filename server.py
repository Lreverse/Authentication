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
global server

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
            login_rq(rq)
        case packet.REGISTER_RQ:
            register_rq(rq)
        case _:
            pass
    return True


def login_rq(data):
    """处理登录请求"""
    print("> login rq: ", data)
    username = data["username"]
    hash2 = data["hashcode"]
    mac = data["MAC"]

    # 查询sql查找对应关系
    cursor = db.cursor()
    sql = f"select * from users where username = '{username}'"  # 查询
    cursor.execute(sql)
    result = cursor.fetchall()

    if not result:
        rs = packet.login_rs_error("user not exit")
    else:
        hash1 = result[0][2]
        hash2_ver = encrypt.hash_salt(mac.encode(), hash1.encode())

        # 验证成功，返回AES(hash1, 认证码)
        if hash2 == hash2_ver:
            hash1_byte = binascii.unhexlify(hash1.encode())  # 将hash1转为字节流
            mac_byte = binascii.unhexlify(mac.encode())  # 将16进制的mac转换为字节流
            cipher = encrypt.AES_Encode(hash1_byte, mac_byte)  # AES加密mac，密钥为hash1
            rs = packet.login_rs_success(cipher)
        # 验证失败，返回error信息
        else:
            rs = packet.login_rs_error("authentication failure")
    response_data = json.dumps(rs)
    server.send(response_data)


def register_rq(data):
    pass


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
