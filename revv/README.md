# Revv

### Overview

In this challenge we are given a 64-bit ELF binary which checks our input against a set of hard-coded characters. After finding the right positions for these characters the flag is revealed

## Analysis

```c
void* fsbase
int64_t canary = *(fsbase + 0x28)
printf(format: "Enter the Password: ")
void pw_input
__isoc99_scanf(format: "%30s", &pw_input)
check_password(&pw_input)
if ((canary ^ *(fsbase + 0x28)) == 0)
    return 0
__stack_chk_fail()
noreturn
```
Looking at the main function in a disassembler we can see that we have a call to a function with our password as input `check_password(&pw_input)`

```c
int64_t output_msg
if (strlen(password) u> 0x19)
    output_msg = puts(str: "Don't try to hack me :D")
else if (strlen(password) != 0x15)
    output_msg = puts(str: "Length mismatch! :(")
else if (password[0x11] != 0x31)
    label_13b2:
    output_msg = puts(str: "Come on, Try Again!! :(")
else
    if (*password != 0x41)
        goto label_13b2
    if (password[1] != 0x43)
        goto label_13b2
    if (password[2] != 0x54)
        goto label_13b2
    if (password[8] != 0x63)
        goto label_13b2
    if (password[3] != 0x46)
        goto label_13b2
    if (password[0xd] != 0x76)
        goto label_13b2
    if (password[5] != 0x4e)
        goto label_13b2
    if (password[6] != 0x30)
        goto label_13b2
    if (password[0xb] != 0x52)
        goto label_13b2
    if (password[7] != 0x31)
        goto label_13b2
    if (password[0xf] != 0x72)
        goto label_13b2
    if (password[9] != 0x65)
        goto label_13b2
    if (password[4] != 0x7b)
        goto label_13b2
    if (password[0xa] != 0x5f)
        goto label_13b2
    if (password[0xc] != 0x33)
        goto label_13b2
    if (password[2] != 0x54)
        goto label_13b2
    if (password[0xe] != 0x33)
        goto label_13b2
    if (password[0x10] != 0x35)
        goto label_13b2
    if (password[0x12] != 0x5e)
        goto label_13b2
    if (password[0x13] != 0x67)
        goto label_13b2
    if (password[0x14] != 0x7d)
        goto label_13b2
    output_msg = puts(str: "Nice job! :)")
return output_msg
```
Here we are in the `check_password()` function and we quickly see that our input gets checked against some hard-coded characters e.g `0x41, 0x43, 0x54`. Now we can go and manually check each of our string positions and match the correct letter but let's not do that and automate this.

## Using Angr

*"angr is an open-source binary analysis platform for Python. It combines both static and dynamic symbolic ("concolic") analysis, providing tools to solve a variety of tasks."* - ![angr](https://angr.io/)
By using ![Symbolic Execution](https://www.cs.cmu.edu/~aldrich/courses/17-355-18sp/notes/notes14-symbolic-execution.pdf) and one of angr's powerful simulation managers we can let a program explore different code paths for us. Using symbolic execution is great in our case because we have a code path that we want angr to explore and find, the code path being the correct input to reach the string **Nice job :)**. Let's code

```python
#!/usr/bin/python

import angr

proj = angr.Project("revv")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Nice job! :)" in s.posix.dumps(1))
password = simgr.found[0].posix.dumps(0)
print(password.decode("utf-8"))
```

```bash
└─$ ./solve.py  
WARNING | 2022-08-12 00:36:05,844 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING | 2022-08-12 00:36:08,210 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff6c with 4 unconstrained bytes referenced from 0x4010e9 (PLT.__isoc99_scanf+0x19 in revv (0x10e9))
WARNING | 2022-08-12 00:36:08,599 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffefb6f with 98 unconstrained bytes referenced from 0x58e410 (strlen+0x0 in libc.so.6 (0x8e410))
ACTF{N01ce_R3v3r51^g}
```

```bash
└─$ ./revv    
Enter the Password: ACTF{N01ce_R3v3r51^g}
Nice job! :)
```


