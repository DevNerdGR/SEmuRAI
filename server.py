from fastmcp import FastMCP
import ghidra_bridge

mcp = FastMCP(name="SEmuRAI")

bridge = None
emuHelper = None


@mcp.tool
def greet(name : str) -> str:
    """Sanity check"""
    return f"Hello, {name}!! :))"

@mcp.tool
def setupEmulator():
    """
    RUN THIS BEFORE ANY EMULATION WORK!
    Running this will also cause emulation session to reset.
    """
    try:
        global bridge
        global emuHelper
        
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

if __name__ == "__main__":
    mcp.run()
