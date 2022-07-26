#!/usr/bin/env python2

import sqlite3
import os
import binascii
import subprocess
import base64
import sys
import hashlib
import glob
import argparse

parser = argparse.ArgumentParser() 
required = parser.add_argument_group('required arguments')
required.add_argument("-p", "--safe-storage-password", required=True, dest="password")
required.add_argument("-i", "--login-data-filepath", required=True, dest="login_data")
#parser.add_argument("-o", "--output-file", default="decrypted-out.txt")
args = parser.parse_args()


# Required variables
loginData = glob.glob(args.login_data)
safeStorageKey = args.password


def pbkdf2_bin(password, salt, iterations, keylen=16):
    _pack_int = struct.Struct('>I').pack
    hashfunc = sha1
    mac = hmac.new(password, None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())

    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]


try:
    from hashlib import pbkdf2_hmac
except ImportError:
    # If hashlib import is not available (Python <2.7.8, macOS < 10.11) use @mitsuhiko's pbkdf2 method above
    pbkdf2_hmac = pbkdf2_bin
    from hashlib import sha1


def chromeDecrypt(encrypted, safeStorageKey):
    #For Chrome default IV is 16 spaces and the salt is 'saltysalt'. For Mac, default iteration is 1003, for Linux it's 1.
    iv = ''.join(('20', ) * 16)
    key = pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]
    hex_key = binascii.hexlify(key)
    hex_enc_password = base64.b64encode(encrypted[3:])
    print("[+] Starting deryption routine...")
    try:
        decrypted = subprocess.check_output(
            "echo {} | openssl enc -base64 -d "
            "-aes-128-cbc -iv '{}' -K {}".format(hex_enc_password, iv, hex_key),
            shell=True)
    except subprocess.CalledProcessError:
        decrypted = "Error decrypting this data"
    return decrypted


def chromeProcess(safeStorageKey, loginData):
    iv = ''.join(('20',) * 16)
    key = hashlib.pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]
    fd = os.open(loginData, os.O_RDONLY) #open as read only
    database = sqlite3.connect('/dev/fd/%d' % fd)
    os.close(fd)
    sql = 'select username_value, password_value, origin_url from logins'
    decryptedList = []
    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
                continue
            else:
                urlUserPassDecrypted = (url.encode('ascii', 'ignore'), user.encode('ascii', 'ignore'), chromeDecrypt(encryptedPass, safeStorageKey).encode('ascii', 'ignore'))
                decryptedList.append(urlUserPassDecrypted)
    return decryptedList

#output = []
for profile in loginData:
    for i, x in enumerate(chromeProcess(safeStorageKey, "%s" % profile)):
    	print "%s[%s]%s %s%s%s\n\t%sUser%s: %s\n\t%sPass%s: %s" % ("\033[32m", (i + 1), "\033[0m", "\033[1m", x[0], "\033[0m", "\033[32m", "\033[0m", x[1], "\033[32m", "\033[0m", x[2])

