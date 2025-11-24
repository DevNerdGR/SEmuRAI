"""
Makes use of Qiling emulaton framework
"""
from qiling import *
import os

class RootFS:
    _base = "/Resources/QilingRootFsTemplates/rootfs/"
    x8664_linux_rootFS = _base + "x8664_linux_glibc2.39/"



class QilingSession:
    def __init__(self, pathToBinary: str, pathToRootFS: str, ghidraBaseAddr: int, args: list=[]):
        self.ql = Qiling(
            [pathToBinary] + args,
            rootfs=os.path.dirname(os.path.abspath(__file__)) + pathToRootFS    
        )
        self.ghidraBase = ghidraBaseAddr
        self.hookedAddrs = set()
        
    
    def ghidraToQilingAddress(self, ghidraAddress):
        return ghidraAddress - self.ghidraBase + self.ql.loader.images[0].base

    def qilingToGhidraAddress(self, qilingAddress):
        return qilingAddress - self.ql.loader.images[0].base + self.ghidraBase

    def setBreakpoint(self, qilingAddr, handler=None):
        if handler == None:
            handler = QilingSession.genericHandler
        self.ql.hook_address(handler, qilingAddr)
        self.hookedAddrs.add(qilingAddr)
    
    def removeBreakpoint(self, qilingAddr):
        self.ql.unhook(qilingAddr)
        self.hookedAddrs.remove(qilingAddr)

    def getBreakpoints(self):
        return set([hex(self.qilingToGhidraAddress(a)) for a in self.hookedAddrs])

    def genericHandler(ql: Qiling):
        ql.emu_stop()

    def setPC(self, qilingAddr):
        self.ql.arch.regs.arch_pc = qilingAddr
    
    def getPC(self):
        return self.qilingToGhidraAddress(self.ql.arch.regs.arch_pc)
    
    def runTillBreak(self):
        try:
            self.ql.run()
            return (True, self.getPC())
        except Exception as e:
            return (False, str(e))
            

    def readRegister(self, reg: str):
        return self.ql.arch.regs.read(reg)
    
    def writeRegister(self, reg: str, value: int):
        self.ql.arch.regs.write(reg, value)
    
    def readMem(self, addr: int, length: int):
        return self.ql.mem.read(addr, length).hex()
    
    def writeMem(self, addr: int, data: bytes):
        self.ql.mem.write(addr, data)