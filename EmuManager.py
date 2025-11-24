"""
Makes use of Qiling emulaton framework
"""
from qiling import *

class RootFS:
    _base = "./Resources/QilingRootFsTemplates/rootfs/"
    x8664_linux_rootFS = _base + "x8664_linux_glibc2.39/"



class QilingSession:
    def __init__(self, pathToBinary: str, pathToRootFS: str, ghidraBaseAddr: int, args: list=[]):
        self.ql = Qiling(
            [pathToBinary] + args,
            rootfs=pathToRootFS
        )
        self.ghidraBase = ghidraBaseAddr
    
    def ghidraToQilingAddress(self, ghidraAddress):
        return ghidraAddress - self.ghidraBase + self.ql.loader.images[0].base

    def setBreakpoint(self, qilingAddr, handler=None):
        if handler == None:
            handler = QilingSession.genericHandler
        
        self.ql.hook_address(handler, qilingAddr)
    
    def genericHandler(ql: Qiling):
        ql.emu_stop()

    def setPC(self, qilingAddr):
        self.ql.arch.regs.arch_pc = qilingAddr
    
    def runTillBreak(self):
        self.ql.run()
        return self.ql.arch.regs.arch_pc