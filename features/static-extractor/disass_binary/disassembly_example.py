#!/usr/bin/python

import pefile
from capstone import *

# load the target PE file
pe = pefile.PE("IRCBot.exe")

# get the address of the program entry point from the program header
entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

# compute memory address where the entry train_model will be loaded into memory
entrypoint_address = entrypoint+pe.OPTIONAL_HEADER.ImageBase

# get the binary train_model from the PE file object
binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint+100]

# initialize disassembler to disassemble 32 bit x86 binary train_model
disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

# disassemble the train_model
for instruction in disassembler.disasm(binary_code, entrypoint_address):
    print("%s\t%s" % (instruction.mnemonic, instruction.op_str))
