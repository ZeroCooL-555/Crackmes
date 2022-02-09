#!/usr/bin/env python3

import sys

# Key generation algorithm

def Gen_Key(name, num):
    passcode = ""
    i = 0
    while i <= len(name):
        if len(name) <= i:
            break
        passcode += chr(int(num) + int(ord(name[i])))
        i += 1
    return passcode

if len(sys.argv) != 3:
    print("usage: ./keygen <username> <number>")
    exit(-1)


username = sys.argv[1]
number = sys.argv[2]
password = Gen_Key(username, number)
print(password)

