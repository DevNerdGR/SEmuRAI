import asyncio
import os
from typing import Optional
from contextlib import AsyncExitStack
from openai import OpenAI

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from dotenv import load_dotenv
from rich import print

load_dotenv()

api_key = os.getenv("LLM_API_KEY")
base_url = os.getenv("LLM_ENDPOINT") 

client = OpenAI(
    api_key=api_key,
    base_url=base_url
)


class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
    # methods will go here

    async def connect_to_server(self, server_script_path: str):
        """Connect to an MCP server

        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        is_python = server_script_path.endswith('.py')
        is_js = server_script_path.endswith('.js')
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")

        command = "python3" if is_python else "node"
        server_params = StdioServerParameters(
            command=command,
            args=[server_script_path],
            env=None
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        await self.session.initialize()

        # List available tools
        response = await self.session.list_tools()
        self.tools = response.tools
        print("\nConnected to server with tools:", [tool.name for tool in self.tools])
    
    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()

async def main():
    c = MCPClient()
    await c.connect_to_server("/home/user/Documents/Projects/SEmuRAI/server_qiling.py")
    await c.cleanup()
    return c.tools

tools = asyncio.run(main())

openai_tools = []
for tool in tools:
    openai_tools.append({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.inputSchema
        }
    })

response = client.chat.completions.create(
    model="DeepSeek-V3-0324",
    messages=[{"role": "user", "content": "what mcp tools do you have access to? answer in a concise list. next, i want you to greet the tool"}],
    tools=openai_tools
)

print(response.choices[0])


