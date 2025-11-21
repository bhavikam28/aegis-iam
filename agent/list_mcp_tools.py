"""
Script to list available MCP tools from AWS IAM and AWS API servers
Run this to see what tools are actually available
"""

import asyncio
from fastmcp_client import FastMCPClient

async def list_tools():
    """List all available MCP tools"""
    client = FastMCPClient()
    
    if await client.connect():
        print("\n=== Listing All Available MCP Tools ===\n")
        
        tools = await client.list_tools()
        
        # Group by server
        iam_tools = [t for t in tools if t.name.startswith('aws-iam_')]
        api_tools = [t for t in tools if t.name.startswith('aws-api_')]
        cloudtrail_tools = [t for t in tools if t.name.startswith('aws-cloudtrail_')]
        
        print(f"📋 Total tools: {len(tools)}\n")
        
        if iam_tools:
            print(f"🔷 AWS IAM MCP Server ({len(iam_tools)} tools):")
            for tool in iam_tools:
                print(f"   - {tool.name.replace('aws-iam_', '')}")
                if hasattr(tool, 'description'):
                    print(f"     {tool.description}")
            print()
        
        if api_tools:
            print(f"🔷 AWS API MCP Server ({len(api_tools)} tools):")
            for tool in api_tools:
                print(f"   - {tool.name.replace('aws-api_', '')}")
                if hasattr(tool, 'description'):
                    print(f"     {tool.description}")
            print()
        
        if cloudtrail_tools:
            print(f"🔷 AWS CloudTrail MCP Server ({len(cloudtrail_tools)} tools):")
            for tool in cloudtrail_tools:
                print(f"   - {tool.name.replace('aws-cloudtrail_', '')}")
            print()
        
        await client.disconnect()
    else:
        print("❌ Failed to connect to MCP servers")

if __name__ == "__main__":
    asyncio.run(list_tools())

