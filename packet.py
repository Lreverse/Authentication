#!/usr/bin/env python3
# -*- coding: utf-8 -*-

base = 0
EXIT_RQ = base + 0
LOGIN_RQ = base + 1
LOGIN_RS_SUCCESS = base + 2
LOGIN_RS_ERROR = base + 3
REGISTER_RQ = base + 4
REGISTER_RS = base + 5
CHANGE_PWD_RQ = base + 6
CHANGE_PWD_RS_SUCCESS = base + 7
CHANGE_PWD_RS_ERROR = base + 8


def exit_rq():
    packet = {
        "type": EXIT_RQ
    }
    return packet


def login_rq(username, mac, hash2):
    packet = {
        "type": LOGIN_RQ,
        "username": username,
        "MAC": mac,
        "hashcode": hash2
    }
    return packet


def login_rs_success(cipher):
    packet = {
        "type": LOGIN_RS_SUCCESS,
        "cipher": cipher
    }
    return packet


def login_rs_error(msg=""):
    packet = {
        "type": LOGIN_RS_ERROR,
        "msg": msg
    }
    return packet


def change_pwd_rq(new_cipher, new_hash2):
    packet = {
        "type": CHANGE_PWD_RQ,
        "new_cipher": new_cipher,
        "new_hash2": new_hash2
    }
    return packet


def change_pwd_rs_success():
    packet = {
        "type": CHANGE_PWD_RS_SUCCESS
    }
    return packet


def change_pwd_rs_error(msg=""):
    packet = {
        "type": CHANGE_PWD_RS_ERROR,
        "msg": msg
    }
    return packet
