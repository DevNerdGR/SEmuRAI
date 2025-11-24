# Setup
1. Install requirements
2. Install [bridge script](https://github.com/justfoxing/ghidra_bridge) in ghidra_scripts
3. Install MCP server in Claude
```json
{
    "SEmuRAI": {
      "command": "python",
      "args": ["absolute/path/to/server.py"]
    }
}

```
4. Start Ghidra and run bridge script