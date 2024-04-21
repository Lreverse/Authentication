#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tcp import *
import packet
import encrypt
import os
import json
import wx
import binascii
import datetime

SERVER_IP = "127.0.0.1"
PORT = 8888
BUFFER_SIZE = 2048
MAC_LENGTH = 16
APP_TITLE = 'Authentication system'
client = None


class User(object):
    def __init__(self, username, pwd):
        self.username = username
        self.pwd = pwd
        self.hash1 = encrypt.hash_md5(username.encode(), pwd.encode())
        self.mac = binascii.hexlify(os.urandom(MAC_LENGTH)).decode()  # 生成认证码(转成16进制)
        self.hash2 = encrypt.hash_salt(self.hash1.encode(), self.mac.encode())


def login_handle(user):
    """登录认证处理函数"""
    # 发送登录请求
    rq = packet.login_rq(user.username, user.mac, user.hash2)
    send_data = json.dumps(rq)  # 序列化
    client.send(send_data)

    # 接收响应
    recv_data = client.recv()
    rs = json.loads(recv_data)  # 反序列化
    pack_type = rs["type"]
    match pack_type:
        case packet.LOGIN_RS_SUCCESS:
            cipher = rs["cipher"]
            cipher_byte = binascii.unhexlify(cipher.encode())
            hash1_byte = binascii.unhexlify(user.hash1.encode())
            mac = encrypt.AES_Decode(hash1_byte, cipher_byte)
            if mac == user.mac:
                with open('client_access.log', 'a') as f:
                    print(datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S '), mac, '', user.username,
                          file=f)  # 写入文件
            return True, ""
        case packet.LOGIN_RS_ERROR:
            msg = rs["msg"]
            # print(msg)
            return False, msg
        case _:
            msg = "packet error"
            # print(msg)
            return False, msg


def register_handle():
    pass


def change_pwd_handle(username: str, new_pwd: str, key: str):
    """修改密码处理函数"""
    new_hash1 = encrypt.hash_md5(username.encode(), new_pwd.encode())
    new_hash1_byte = binascii.unhexlify(new_hash1.encode())
    key_byte = binascii.unhexlify(key.encode())
    new_cipher = encrypt.AES_Encode(key_byte, new_hash1_byte)
    new_hash2 = encrypt.hash_salt(key.encode(), new_cipher.encode())

    # 发送更改密码请求
    rq = packet.change_pwd_rq(new_cipher, new_hash2)
    send_data = json.dumps(rq)  # 序列化
    client.send(send_data)

    # 接收响应
    recv_data = client.recv()
    rs = json.loads(recv_data)  # 反序列化
    pack_type = rs["type"]
    match pack_type:
        case packet.CHANGE_PWD_RS_SUCCESS:
            return True, ""
        case packet.CHANGE_PWD_RS_ERROR:
            msg = rs["msg"]
            return False, msg
        case _:
            msg = "packet error"
            return False, msg


class IndexPanel(wx.Panel):
    """索引面板"""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent

        # 生成控件
        info = "Welcome to Lyp's server"
        self.wel_info = wx.StaticText(self, -1, info, pos=(70, 50), size=(250, -1), style=wx.ALIGN_CENTRE_HORIZONTAL)
        self.lg_btn = wx.Button(self, -1, pos=(70, 100), size=(100, 30), label="login")
        self.reg_btn = wx.Button(self, -1, pos=(220, 100), size=(100, 30), label="register")

        # 绑定事件
        self.lg_btn.Bind(wx.EVT_BUTTON, self.login_api)
        self.reg_btn.Bind(wx.EVT_BUTTON, self.register_api)

        # self.Hide()

    def login_api(self, event=None):
        self.Hide()
        self.parent.login_panel.Show()
        self.parent.Layout()

    def register_api(self, event=None):
        self.Hide()
        self.parent.register_panel.Show()
        self.parent.Layout()


class LoginPanel(wx.Panel):
    """登录面板"""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent

        wx.StaticText(self, -1, "username", pos=(60, 60))
        wx.StaticText(self, -1, "password", pos=(60, 100))
        self.username = wx.TextCtrl(self, -1, '', pos=(140, 60), size=(175, -1), style=wx.TE_CENTER)
        self.password = wx.TextCtrl(self, -1, '', pos=(140, 100), size=(175, -1), style=wx.TE_CENTER | wx.TE_PASSWORD)
        self.login_btn = wx.Button(self, -1, label="login", pos=(140, 150))
        self.back_btn = wx.Button(self, -1, label="back", pos=(240, 150))

        self.login_btn.Bind(wx.EVT_BUTTON, self.on_login)
        self.back_btn.Bind(wx.EVT_BUTTON, self.on_back)
        self.Hide()

    # 向服务器发送登录请求
    def on_login(self, event):
        # 启动tcp客户端
        global client
        client = tcpClient(SERVER_IP, PORT, BUFFER_SIZE)
        client.connect()
        print("> ", client.recv())

        # 获取用户名密码并发送登录请求
        username = self.username.GetValue()
        password = self.password.GetValue()
        user = User(username, password)
        flag, msg = login_handle(user)
        self.username.SetValue("")  # 重置输入框
        self.password.SetValue("")  # 重置输入框
        if flag:
            # 发送成功
            self.parent.success_panel.username = username
            self.parent.success_panel.hash1 = user.hash1
            self.parent.success_panel.info.SetLabel(f"Hello ^_^  {username}")
            self.Hide()
            self.parent.success_panel.Show()
            self.parent.Layout()
        else:
            # 发送失败，结束tcp连接
            client.send(json.dumps(packet.exit_rq()))
            client.close()
            wx.MessageBox(msg, "alert", wx.OK | wx.ICON_WARNING)

    # 返回到主界面
    def on_back(self, event):
        self.Hide()
        self.parent.index_panel.Show()
        self.parent.Layout()


class RegisterPanel(wx.Panel):
    """注册面板"""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent

        # 控件
        wx.StaticText(self, -1, "username", pos=(60, 30))
        wx.StaticText(self, -1, "password", pos=(60, 70))
        wx.StaticText(self, -1, "phone NO", pos=(60, 110))
        self.username = wx.TextCtrl(self, -1, '', pos=(140, 30), size=(175, -1), style=wx.TE_CENTER)
        self.password = wx.TextCtrl(self, -1, '', pos=(140, 70), size=(175, -1), style=wx.TE_CENTER | wx.TE_PASSWORD)
        self.phone_no = wx.TextCtrl(self, -1, '', pos=(140, 110), size=(175, -1), style=wx.TE_CENTER)
        self.login_btn = wx.Button(self, -1, label="register", pos=(140, 155))
        self.back_btn = wx.Button(self, -1, label="back", pos=(240, 155))
        self.Hide()

        self.login_btn.Bind(wx.EVT_BUTTON, self.on_register)
        self.back_btn.Bind(wx.EVT_BUTTON, self.on_back)

    def on_register(self, event=None):
        self.username.SetValue("")
        self.password.SetValue("")
        self.phone_no.SetValue("")

    def on_back(self, event=None):
        self.Hide()
        self.parent.index_panel.Show()
        self.parent.Layout()


class SuccessPanel(wx.Panel):
    """登录成功的面板"""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent
        self.username = None
        self.hash1 = None

        self.info = wx.StaticText(self, -1, "Hello ^_^", pos=(70, 50), size=(250, -1), style=wx.ALIGN_CENTRE_HORIZONTAL)
        self.change_pwd_btn = wx.Button(self, -1, label="change pwd", pos=(70, 100), size=(100, 30))
        self.exit_btn = wx.Button(self, -1, label="exit", pos=(220, 100), size=(100, 30))

        self.change_pwd_btn.Bind(wx.EVT_BUTTON, self.on_change_pwd)
        self.exit_btn.Bind(wx.EVT_BUTTON, self.on_exit)
        self.Hide()

    def on_change_pwd(self, event=None):
        self.parent.change_pwd_panel.username = self.username
        self.parent.change_pwd_panel.hash1 = self.hash1
        self.Hide()
        self.parent.change_pwd_panel.Show()
        self.parent.Layout()

    def on_exit(self, event=None):
        self.parent.Destroy()


class ChangePwdPanel(wx.Panel):
    """修改密码面板"""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent
        self.username = None
        self.hash1 = None

        self.info = wx.StaticText(self, -1, "input your pwd to change（˙Ꙫ˙）", pos=(70, 30), size=(250, -1),
                                  style=wx.ALIGN_CENTRE_HORIZONTAL)
        wx.StaticText(self, -1, "password", pos=(60, 70))
        wx.StaticText(self, -1, "confirm", pos=(60, 110))
        self.new_password = wx.TextCtrl(self, -1, '', pos=(140, 70), size=(175, -1),
                                        style=wx.TE_CENTER | wx.TE_PASSWORD)
        self.confirm = wx.TextCtrl(self, -1, '', pos=(140, 110), size=(175, -1), style=wx.TE_CENTER | wx.TE_PASSWORD)
        self.submit_btn = wx.Button(self, -1, label="submit", pos=(140, 155))
        self.back_btn = wx.Button(self, -1, label="back", pos=(240, 155))

        self.submit_btn.Bind(wx.EVT_BUTTON, self.on_submit)
        self.back_btn.Bind(wx.EVT_BUTTON, self.on_back)
        self.Hide()

    # 向服务器发送登录请求
    def on_submit(self, event=None):
        new_pwd = self.new_password.GetValue()
        flag, msg = change_pwd_handle(self.username, new_pwd, self.hash1)

        # 提交成功
        self.new_password.SetValue("")
        self.confirm.SetValue("")
        if flag:
            wx.MessageBox("password has been changed!", "success", wx.OK | wx.ICON_INFORMATION)
            self.Hide()
            self.parent.success_panel.Show()
            self.parent.Layout()
        else:
            wx.MessageBox(msg, "alert", wx.OK | wx.ICON_WARNING)

    # 返回到主界面
    def on_back(self, event=None):
        self.Hide()
        self.parent.success_panel.Show()
        self.parent.Layout()


class MainFrame(wx.Frame):
    """程序主窗口"""

    def __init__(self):
        wx.Frame.__init__(self, None, -1, APP_TITLE, style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER ^ wx.MAXIMIZE_BOX)
        # style设置了窗口最大化，从而无法进行缩放

        self.index_panel = IndexPanel(self)
        self.login_panel = LoginPanel(self)
        self.register_panel = RegisterPanel(self)
        self.success_panel = SuccessPanel(self)
        self.change_pwd_panel = ChangePwdPanel(self)

        # 设置窗口样式
        self.SetBackgroundColour(wx.Colour(224, 224, 224))
        self.SetSize((400, 250))
        self.Center()

        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.vbox.Add(self.index_panel, 1, wx.EXPAND)
        self.vbox.Add(self.login_panel, 1, wx.EXPAND)
        self.vbox.Add(self.register_panel, 1, wx.EXPAND)
        self.vbox.Add(self.success_panel, 1, wx.EXPAND)
        self.vbox.Add(self.change_pwd_panel, 1, wx.EXPAND)
        self.SetSizer(self.vbox)

        self.Layout()


class MainApp(wx.App):
    """主程序"""

    def OnInit(self):
        self.SetAppName(APP_TITLE)
        self.frame = MainFrame()
        self.frame.Show()
        return True

    def OnExit(self):
        global client
        if client is not None:
            client.send(json.dumps(packet.exit_rq()))
            client.close()
        return 1


if __name__ == '__main__':
    app = MainApp()
    app.MainLoop()

    # user = User("lily", "123456")
    # print(">: ", client.recv())
    # login(user)
