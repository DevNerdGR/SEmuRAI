import os
from dotenv import load_dotenv
from openai import OpenAI, AsyncOpenAI
from agents import Agent, Runner, OpenAIResponsesModel
import subprocess, json
from Backend.LLMInterface import *

# Load environment variables from .env file
load_dotenv(".env")

# Get API key from environment variables
api_key = os.getenv("LLM_API_KEY")
base_url = os.getenv("LLM_ENDPOINT")  # Optional: for custom endpoints
name = os.getenv("LLM_MODEL_NAME") 
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


s = SimpleAnalysisSession(api_key=api_key, endpoint=base_url, modelName=name)





# Initialize OpenAI clie
# Send request with the prompt

response = s.sendMessage("can you call the resource thing in cyberchef")

# Print the response
print(response)

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