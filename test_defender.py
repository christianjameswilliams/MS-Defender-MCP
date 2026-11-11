import asyncio
from mcp import Client


async def main():
    async with Client("http://127.0.0.1:8000/mcp") as client:

        print("Connected to MCP server.")
        print("Running Defender Advanced Hunting query...")
        print()

        result = await client.call_tool(
            "run_hunting_query",
            {
                "query": "DeviceInfo | where Timestamp > ago(24h) | take 5"
            }
        )

        print(result)


asyncio.run(main())