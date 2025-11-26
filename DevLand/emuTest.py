from EmuManager import QilingSession
from EmuManager import RootFS
import ghidra_bridge

print(f"Root fs: {RootFS.x8664_linux_rootFS}")

b = ghidra_bridge.GhidraBridge(namespace=globals())

ghidraBase = int(currentProgram.getImageBase().toString(), 16)

print(f"{ghidraBase=}")

s = QilingSession("./Tests/SimpleTest/SimpleTest", RootFS.x8664_linux_rootFS, ghidraBase)

print(s)
print(f"{hex(s.ql.loader.images[0].base)}")

s.setPC(s.ghidraToQilingAddress(0x10115c))

interest = 0x10117c

s.setBreakpoint(s.ghidraToQilingAddress(interest))
print(f"PC: {hex(s.ql.arch.regs.arch_pc)}")
print(f"bp={hex(s.ghidraToQilingAddress(interest))}")
s.runTillBreak()

print(f"PC: {hex(s.ql.arch.regs.arch_pc)}")
print(f"EDI: {hex(s.ql.arch.regs.read("edi"))}")
print(f"ESI: {hex(s.ql.arch.regs.read("esi"))}")