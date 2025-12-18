import os
from dotenv import load_dotenv
from openai import OpenAI, AsyncOpenAI, RateLimitError
from agents import Agent, Runner, OpenAIResponsesModel
import subprocess, json

# Load environment variables from .env file
load_dotenv(".env")

# Get API key from environment variables
api_key = os.getenv("LLM_API_KEY")
base_url = os.getenv("LLM_ENDPOINT")  # Optional: for custom endpoints
print(api_key)

"""
model = OpenAIResponsesModel(
    model="o3-mini",
    openai_client=AsyncOpenAI(api_key=api_key)
)
"""

client = OpenAI(
    api_key=api_key,
    base_url=base_url
)



# Initialize OpenAI clie
# Send request with the prompt

response = client.chat.completions.create(
    model="DeepSeek-V3-0324",
    messages=[{"role": "user", "content": "what mcp tools do you have access to?"}],
    tools=[
        {
            "type": "mcp",
            "server": {
                "command": "python3",
                "args": ["/home/user/Documents/Projects/SEmuRAI/server_qiling.py"],
                "env": {}
            }
        }
    ]
)


# Print the response
print(response.choices[0].message)
"""
def load_mcp_tools_stdio():
    proc = subprocess.Popen(
        ["python3", "/home/user/Documents/Projects/SEmuRAI/server_qiling.py"],
        stdout=subprocess.PIPE,
        text=True
    )

    out = proc.stdout.read()
    mcp_tools = json.loads(out)
    
    # Convert MCP → OpenAI format
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("parameters", {})
            }
        }
        for t in mcp_tools
    ]

print(load_mcp_tools_stdio())
"""