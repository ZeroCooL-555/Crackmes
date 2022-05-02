# Forest

## Summary

in this challenge the reverser is tasked to reverse and pass simple if statements/checks to generate correct keys to the program.

# Analysis

After extracting the binary and looking at the functions present within it with `nm` we get a very short list of functions like we can see here

```bash
0000000000001318 T _fini
0000000000001310 T __libc_csu_fini
00000000000012a0 T __libc_csu_init
0000000000001080 T main
00000000000011a0 T _start
```

Running strings on the binary doesn't give us anything juicy to work with either, but we do get some information on what functions are being called in the binary for example sqrt,puts,printf etc.

```bash
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
sqrt
__isoc99_scanf
puts
__stack_chk_fail
printf
__cxa_finalize
__libc_start_main
libm.so.6
libc.so.6
GLIBC_2.2.5
GLIBC_2.7
GLIBC_2.4
u3UH
[]A\A]A^A_
The forest is dark and dangerous. Be careful!
You escaped the forest.
Flag is correct.
The forest is unforgiving.
Flag not correct.
Please enter the flag:
%13s
<...>
```

Let's open the binary up in IDA and have a look at the `main` function's pseudo-code

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[14]; // [rsp+Ah] [rbp-1Eh] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-10h]

  v5 = __readfsqword(0x28u);
  puts("The forest is dark and dangerous. Be careful!");
  printf("Please enter the flag:");
  __isoc99_scanf("%13s", v4);
  if ( v4[0] == 114
    && v4[1] % 10 == 1
    && sqrt((double)v4[2]) * 5.0 == 50.0
    && (unsigned __int8)(v4[3] - 1) <= 0x71u
    && v4[4] == 105
    && v4[5] == 100
    && v4[6] == 105
    && v4[7] == 110
    && v4[8] == 103
    && v4[9] == 104
    && v4[10] == 111
    && v4[11] == 111
    && v4[12] == 100 )
  {
    printf("You escaped the forest.\nFlag is correct.");
  }
  else
  {
    printf("The forest is unforgiving.\nFlag not correct.");
  }
  return 0;
}
```

Here we have a fairly nice decompilation of the binaries main function and we can see what the binary does to validate a key. After quickly skimming through the code we can confidently rename some of the variables to better our understanding of the binary.
- `v4 ==> our key`
- `v5 ==> canary`


### Breakdown

We can see that after our first and fourth character input the program only checks individual letters ex: `105,100,110,111` so we can convert these values to ASCII and get the corresponding letters `r???idinghood`Now we only have to focus on the second, third and fourth characters of the key.

- `v4[1] % 10 == 1`
- `sqrt((double)v4[2]) * 5.0 == 50.0`
- `(unsigned __int8)(v4[3] - 1) <= 0x71u`

Our second character input should equal *1* when modded with the value *10*, our third character input should equal *50.0* after being squared and multiplied with the number *5* and the last check takes our input and subtracts *1* from it and compares it to a letter `113`. The square check is a very easy check for us because there is only one letter in the alphabet that equals that value and that's the letter `d`. We can verify that with a simple one-liner list comprehension in python after importing the string library `[string.ascii_letters[x] for x in range(len(string.ascii_letters)) if round((sqrt(ord(string.ascii_letters[x])) * 5.0), 1) == 50.0`
Now we should have only two characters of a valid key missing `r?d?idinghood` The last two checks have multiple valid alphabetical letters so instead of finding many of them by hand we can create a program to find some of the valid variations for us.

# Keygen

```python
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

```

```bash
┌─[user@parrot]─[~/CTF/crackmes.one]
└──╼ $./keygen.py 5
[+] Generated:  redaidinghood
[+] Generated:  rodbidinghood
[+] Generated:  rydcidinghood
[+] Generated:  rGddidinghood
[+] Generated:  rQdeidinghood

Keys Generated: 5
┌─[user@parrot]─[~/CTF/crackmes.one]
└──╼ $./forest 
The forest is dark and dangerous. Be careful!
Please enter the flag:rodbidinghood
You escaped the forest.
Flag is correct.
```
