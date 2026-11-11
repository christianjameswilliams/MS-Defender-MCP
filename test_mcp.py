import asyncio
from mcp import Client


async def main():
    async with Client("http://127.0.0.1:8000/mcp") as client:
        tools = await client.list_tools()

        print("Connected successfully!")
        print()
        print("Available tools:")

        for tool in tools.tools:
            print(f"- {tool.name}")


asyncio.run(main())