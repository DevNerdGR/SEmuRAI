from fastmcp import FastMCP
import ghidra_bridge

mcp = FastMCP(name="SEmuRAI")

bridge = None
emuHelper = None
breakpoints = set()

@mcp.tool
def greet(name : str) -> str:
    """Sanity check"""
    return f"Hello, {name}!! :))"

@mcp.tool
def setupEmulator():
    """
    RUN THIS BEFORE ANY EMULATION WORK!
    Running this will also cause emulation session to reset.

    After setting up the emulator, remember to hook std library calls using hookStdFunction MCP function to properly emulate std library functions.
    """
    try:
        global bridge
        global emuHelper
        global breakpoints
        
        breakpoints = set()
        bridge = ghidra_bridge.GhidraBridge(namespace=globals())
        
        currentProgram = bridge.remote_eval("currentProgram") # Sanity check    
        if currentProgram is None:
            return "No program currently loaded in Ghidra"
        
        EmulatorHelper = bridge.remote_import("ghidra.app.emulator.EmulatorHelper")
        emuHelper = EmulatorHelper(currentProgram)
        return "Emulator session set up."
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def getCurrentProgramName() -> str:
    """Get name of current loaded program, second sanity check"""
    global bridge
    global emuHelper
    try:
        if bridge is None:
            return "Setup required before usage. Run setupEmulator()"
        return bridge.remote_eval("currentProgram.getName()")
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def readRegister(registerName : str) -> int:
    """Reads the value in the specified register"""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        return emuHelper.readRegister(registerName)
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def writeRegister(value : int, registerName : str) -> None:
    """Writes the value in the specified register. Take note of endianess"""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        emuHelper.writeRegister(registerName, value)
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def readMemory(startAddress : str, length : int) -> str:
    """Reads n number of bytes (specified by length parameter) from startAddress. Make sure startAddress starts with 0x. Bytes read are parsed and returned as a hex string."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()
        addr = addressFactory.getAddress(startAddress)

        return "".join([f"{(b & 0xff):02x}" for b in emuHelper.readMemory(addr, length)])

    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def readNullTerminatedString(startAddress : str, maxLength=100) -> str:
    """Reads bytes up to n bytes (specified by maxLength parameter) or when null character is read, whichever is ealier, from startAddress. Bytes are converted to characters and subsequently a string. Make sure startAddress starts with 0x."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()
        addr = addressFactory.getAddress(startAddress)

        return emuHelper.readNullTerminatedString(addr, maxLength)

    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def writeMemory(startAddress : str, bytesToWrite : str) -> None:
    """Write bytes (specified by bytesToWrite in hex string format) from startAddress onwards. Make sure startAddress starts with 0x. Bytes must be supplied as hex string."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()
        bytesToWrite.replace("0x", "")
        byteArr = bytes([int(bytesToWrite[i:i+2], 16) for i in range(0, len(bytesToWrite), 2)])
        emuHelper.writeMemory(addressFactory.getAddress(startAddress), byteArr)

    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def setBreakpoint(address : str) -> None:
    """Establishes a breakpoint at the specified address. Make sure address starts with 0x"""
    global bridge
    global emuHelper
    global breakpoints
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()
        emuHelper.setBreakpoint(addressFactory.getAddress(address))
        breakpoints.add(address)
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def removeBreakpoint(address : str) -> None:
    """Removes breakpoint at the specified address. Make sure address starts with 0x"""
    global bridge
    global emuHelper
    global breakpoints
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()
        breakpoints.remove(address)
        emuHelper.clearBreakpoint(addressFactory.getAddress(address))
    except KeyError as e:
        return f"Breakpoint not set at {address}"
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def getBreakpoints() -> set:
    """Returns set containing addresses of breakpoints."""
    global bridge
    global emuHelper
    global breakpoints
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        return breakpoints
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def stepInstruction() -> None:
    """Steps emulation by one instruction. To make this meaningful, ensure that memory/registers and breakpoints are set up."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        tm = bridge.remote_import("ghidra.util.task.TaskMonitor")
        emuHelper.step(tm.DUMMY)
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"


@mcp.tool
def run() -> str:
    """Starts emulation from address pointed to by program counter/instruction pointer. Will stop when breakpoint hit. To make this meaningful, ensure that memory/registers and breakpoints are set up."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        tm = bridge.remote_import("ghidra.util.task.TaskMonitor")
        done = emuHelper.run(tm.DUMMY)
        return "Emulation started. Ensure enough time has passed before reading results to ensure emulation runs to completion."
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def hookStdFunction(address : str, functionName : str) -> str:
    """Hooks standard library function calls and emulates their functionlity. Pass the name of the respective functions (e.g. printf) to the functionName parameter."""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
    
        currentProgram = bridge.remote_eval("currentProgram")
        addressFactory = currentProgram.getAddressFactory()

        if functionName.lower().strip() == "printf":
            addr = addressFactory.getAddress(hex(emuHelper.readRegister("RDI")))
            return f"Printed string: {emuHelper.readNullTerminatedString(addr, 500)}"
        else:
            return f"Hook unavailable for function {functionName}"
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"
    

@mcp.tool
def getLastError() -> str:
    """Diagnostic function that provides information if emulation fails"""
    global bridge
    global emuHelper
    try:
        if bridge is None or emuHelper is None:
            return "Setup required before usage. Run setupEmulator()"
        return emuHelper.getLastError()
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def hexToDecimal(hexValue : str) -> int:
    """Converts hexadecimal value into its decimal representation. Hexadecimal value must start with 0x. Use this whenever you need to do a conversion, do not do it on your own."""
    if not hexValue.startswith("0x"):
        return "Argument needs to start with 0x"
    return int(hexValue.replace("0x", "").strip(), 16)  

if __name__ == "__main__":
    mcp.run()
