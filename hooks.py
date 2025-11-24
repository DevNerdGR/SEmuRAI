class HookManager:
    defaultFunctionsNameList = ["printf"]
    def __init__(self, emuHelper, functionsNameList=None):
        self.emuHelper = emuHelper
        self.currentProgram = self.emuHelper.getProgram()
        self.funcNames = HookManager.defaultFunctionsNameList if functionsNameList is None else functionsNameList
        self.extFuncEntryRegistry = {}
        self.funcRefs = {}
        rm = self.currentProgram.getReferenceManager()
        em = self.currentProgram.getExternalManager()
        
        for lib in em.getExternalLibraryNames():
            for loc in em.getExternalLocations(lib):
                if loc.getLabel() in self.funcNames:
                    self.extFuncEntryRegistry.update({loc.getLabel(): loc.getAddress()})

        for funcName, funcEntry in self.extFuncEntryRegistry:
            refs = [int(ref.getFromAddress().tostring(), 16) for ref in rm.getReferencesTo(funcEntry)]
            self.funcRefs.update({funcName: refs})
        
    def getHookedRefs(self):
        return self.funcRefs
    
    def getHookedAddresses(self):
        return list(self.funcRefs.values)
    
    def process(self, addr):
        func = next((k for k, v in self.funcRefs.items() if v.contains(addr)), None)

        if func == "printf":
            return "printf called"