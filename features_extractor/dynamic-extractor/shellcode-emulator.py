from qiling import *

# Ne fonctionne pas
shellcode = b"\x41\x4a"  # inc ecx; dec edx

# initialize emulator (x86 linux)
ql = Qiling(shellcoder=shellcode,
            rootfs="qiling/examples/rootfs/x86_linux/",
            ostype="linux",
            archtype="x86",
            output="disasm")

# set machine registers
ql.reg.ecx = 0x3
ql.reg.edx = 0x7
# start emulation
ql.run()
# read machine registers
print("ecx = 0x{:x}".format(ql.reg.ecx))
print("edx = 0x{:x}".format(ql.reg.edx))
