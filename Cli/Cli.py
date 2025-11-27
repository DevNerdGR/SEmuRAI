import argparse
import os
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from CliUtils import styleTypes as st
from CliUtils import *
from rich.console import Console
from rich.panel import Panel


parser = argparse.ArgumentParser(description="SEmuRAI — Software Emulation & Reversing AI Agent")
parser.add_argument("--pretty", type=bool, default=True, help="If set as false, ASCII art and banners will not be printed.")

args = parser.parse_args()

cs = Console()

printBanner(cs) if args.pretty else None


load_dotenv(".env")

apiKey, endpoint, modelName = None, None, None
try:
    cs.print("Loading .env variables...", style=st.info)
    apiKey = os.getenv("LLM_API_KEY")
    endpoint = os.getenv("LLM_ENDPOINT")
    modelName = os.getenv("LLM_MODEL_NAME")
    cs.print("Load .env variables ok.", style=st.info)
except Exception as e:
    cs.print("Unable to load .env variables!", style=st.warning)
    apiKey = cs.input("Enter API key: ").strip() if apiKey is None else True
    endpoint = cs.input("Enter endpoint: ").strip() if endpoint is None else True
    modelName = cs.input("Enter model name: ").strip() if modelName is None else True

printSetupSteps(cs)
cs.input("Press enter when ready.\n")
cs.print("Agent ready.\n", style=st.info)



