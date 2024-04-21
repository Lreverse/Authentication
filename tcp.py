#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from socket import *


class tcpClient(object):
    """tcp客户端"""

    def __init__(self, ip, port, buffer_size):
        self.ip = ip
        self.port = port
        self.buffer_size = buffer_size
        self.socket = None

    def connect(self):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect((self.ip, self.port))
        print(f"connect to {self.ip}:{self.port}")

    def send(self, data):
        num = self.socket.send(data.encode())
        return num

    def recv(self):
        data = self.socket.recv(self.buffer_size).decode()
        return data

    def close(self):
        self.socket.close()


class tcpServer(object):
    """tcp服务器端"""

    def __init__(self, ip, port, buffer_size):
        self.ip = ip
        self.port = port
        self.buffer_size = buffer_size
        self.socket = None
        self.accept_socket = None
        self.client_addr = None
        self.username = None  # 当前连接的用户名
        self.hash1 = None  # 当前连接的用户的密码散列值

    def bind(self):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.bind((self.ip, self.port))

    def listen(self):
        self.socket.listen(5)
        print(f"server is running at {self.ip}:{self.port}")

    def accept(self):
        self.accept_socket, self.client_addr = self.socket.accept()
        print(f"connection from {self.client_addr[0]}:{self.client_addr[1]}")

    def send(self, data):
        num = self.accept_socket.send(data.encode())
        return num

    def recv(self):
        data = self.accept_socket.recv(self.buffer_size).decode()
        return data

    def accept_close(self):
        self.accept_socket.close()
