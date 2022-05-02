#!/usr/bin/python3

from math import sqrt
import string
import random
import sys

def main():
    MAX_KEYS = 44
    if len(sys.argv) < 2:
        print("=====================================")
        print("Key Generator for FOREST - ZeroC001")
        print("=====================================")
        print("           Maximum Keys              ")
        print("                44                   ")
        print("\nUsage: ./keygen.py <number of keys>")
    elif int(sys.argv[1]) > MAX_KEYS:
        [print("[+] Generated: ", x) for x in CreateKeys(MAX_KEYS)]
        print(f"\nKeys Generated: {MAX_KEYS}")
    elif int(sys.argv[1]) < MAX_KEYS:
        [print("[+] Generated: ", x) for x in CreateKeys(int(sys.argv[1]))]
        print(f"\nKeys Generated: {sys.argv[1]}")

def CreateKeys(num_of_keys):
    VALID_KEYS = []
    mod_10 = [string.ascii_letters[x] for x in range(len(string.ascii_letters)) if ord(string.ascii_letters[x]) % 10 == 1]
    ord_list = [string.ascii_letters[x] for x in range(len(string.ascii_letters)) if (ord(string.ascii_letters[x]) - 1) <= 113]
    key_place_holder = ["r","x","d","x","i","d","i","n","g","h","o","o","d"]
    padding = len(ord_list) - len(mod_10)
    mod_10 += [''] * padding
    for l1,l2 in zip(mod_10, ord_list):
        if l1:
            key = [x for x in ''.join(key_place_holder)]
            key[1] = str(l1)
            key[3] = str(l2)
            VALID_KEYS.append(''.join(key))
        else:
            key = [x for x in ''.join(key_place_holder)]
            key[1] = str(random.choice(mod_10[0:5]))
            key[3] = str(l2)
            VALID_KEYS.append(''.join(key))
        if len(VALID_KEYS) == num_of_keys:
            break
    return VALID_KEYS

if __name__ == "__main__":
    main()
