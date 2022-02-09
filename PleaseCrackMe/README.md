# PleaseCrackMe


|  Author  |     Language  |    Platform     | Difficulty |  Quality   |  Arch  |
| -------- | ------------- | --------------  | ---------- | ---------  | ------ |
|  RaphDev |      C/C++    | Unix/Linux etc. |  1.4 Rate! | 4.5 Rate!  | x86-64 |


## Overview

In this challenge the reverser is expected to reverse engineer a letter incrementor function to then create a program (keygen) to generate valid passwords from user entered usernames.

### Analysis

After having downloaded and extracted the binary from the zip file we are left with a ELF 64-bit binary which does not seem to be stripped.

### Strings

My first goto tool to take a quick look at any printable characters of any executable binary is `strings`. Running the strings command against this binary doesn't give us the best result but it does give us a hint of what our next step should be.

```
strings <crackme>

/lib64/ld-linux-x86-64.so.2
libc.so.6
__isoc99_scanf
puts   
__stack_chk_fail
printf        
strlen   
__cxa_finalize
strcmp
__libc_start_main
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH       
[]A\A]A^A_ 
Type in your Username: 
Type in a number beetween 1 and 9: 
Error: Number is too small
Error: Number is too big
Type in the password: 
You are succesfully logged in                                 
Wrong password
<....>

```


### Readelf

The next step is to take a look at the functions present in the binary, we can do that with a tool called `readelf`. Looking a the functions in the binary by running the command `readelf -s <crackme> | grep FUNC` we can see that the only function thats of interest is the `main` function.

![Readelf](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Readelf.png)


### Binary Ninja - Decompilation

Now that we know what to look for we can jump right into a disassembler/decompiler and start figuring out what the binary does. I will be using Binary ninja to view the decompilation of the binary but any other disassembler/decompiler should work just fine.

![Split-view](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Split-view.png)

Looking at the split view we can see that the main function isn't that large, which means that reversing it will be quick and easy. On the right hand side we can see the linear view of the main function in HLIL (High level IL). Let's step through the code and figure out what it's doing.

![Main](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Pseudo-C.png)

Going from HLIL to Pseudo C cleans up the decompilation a bit and makes our lives easier. First of all we can see that on the third line the binary prints to stdout using `printf()` and then asks the user for a username, after the user provides the username it proceeds to ask the user to input a number between 1 and 9 and lastly it asks the user for a password. After renaming a copule of variables we should have something that looks like this.

![Scanf-rename](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/scanf-rev.png)

Going a little further down the function we come across an if/else statement and a while loop. After a little bit of thinking and reasoning we should have something similar-looking to this.

![Reversed](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Reversed.png)


Let's break it down.


### Breaking down the algorithm


![Breakdown](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Detail.png)


We already know that we cannot input any number lower or greater than 9, with that in mind we can move to the while loop and break that loop down to small snippets to comprehend the full picture. It starts off by comparing the lenght of the username with the incrementor/loop counter `i` If the loop counter is greater or equal to the lenght of the username string it breaks out of the loop. Our next line of code is the one we are interested in, it starts of by adding the number that the user chose to the letter indexed by `i` and then stores it in the `password_real` variable also at the `i` index, then we increment `i` each loop. When we add the number we chose to a letter stored at the index we get the letter that's x many numbers away from that letter (e.g a + 3 = d, a + 2 = c e.t.c)

### Testing a password

Now that we understand what is going on we can come up with a valid password. Let's input the username `lol` and use the number `3` When we are prompted for a password we can try the password `oro` Because we know that

```
l + 3 = o
o + 3 = r
l + 3 = o
```

![Successful-login](https://github.com/ZeroCooL-555/Crackmes/blob/master/PleaseCrackMe/Pictures/Success-login.png)



### Creating a keygen

```python

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

```

