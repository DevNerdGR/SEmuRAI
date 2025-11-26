from rich.console import Console
from rich.panel import Panel

def printBanner(console: Console):
    console.print(Panel(banner), justify="center", style="magenta")
    console.print()

def printSetupSteps(console: Console):
    console.print(steps, style=styleTypes.prompt)

banner = r"""
    _______. _______ .___  ___.  __    __  .______          ___       __  
    /       ||   ____||   \/   | |  |  |  | |   _  \        /   \     |  | 
   |   (----`|  |__   |  \  /  | |  |  |  | |  |_)  |      /  ^  \    |  | 
    \   \    |   __|  |  |\/|  | |  |  |  | |      /      /  /_\  \   |  | 
.----)   |   |  |____ |  |  |  | |  `--'  | |  |\  \----./  _____  \  |  | 
|_______/    |_______||__|  |__|  \______/  | _| `._____/__/     \__\ |__| 

[bold]Software Emulation & Reversing AI Agent[/bold]                                                           
"""

steps = r"""
[bold]Setup steps:[/bold]
1. Ensure that you have Ghidra running, with the binary of interest loaded.
2. Ensure that the Ghidra bridge extension is running in your Ghidra instance.
3. Ensure that you have the ghidraMCP plugin installed and enabled in your Ghidra instance.
[bold]For more information, do check out the README file.[/bold]
"""


# Colour definitions
class styleTypes:
    info = "cyan"
    warning = "magenta"
    error = "red"
    prompt = "white"