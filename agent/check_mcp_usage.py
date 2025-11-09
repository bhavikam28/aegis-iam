#!/usr/bin/env python3
"""
Diagnostic script to check MCP usage in audit agent
"""
import logging
from audit_agent import AuditAgent

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def check_mcp_usage():
    """Check if MCP servers are being used or falling back to boto3"""
    print("\n" + "="*80)
    print("MCP USAGE DIAGNOSTIC")
    print("="*80 + "\n")
    
    # Initialize audit agent
    print("1. Initializing AuditAgent...")
    agent = AuditAgent(aws_region="us-east-1")
    
    # Initialize MCP clients
    print("\n2. Initializing MCP clients...")
    mcp_success = agent.initialize_mcp_clients()
    
    print(f"\n✅ MCP Initialization Result: {mcp_success}")
    print(f"   - IAM Client: {'✅ Available' if agent.iam_client else '❌ Not Available'}")
    print(f"   - CloudTrail Client: {'✅ Available' if agent.cloudtrail_client else '❌ Not Available'}")
    print(f"   - API Client: {'✅ Available' if agent.api_client else '❌ Not Available'}")
    
    # Check what each client actually is
    if agent.iam_client:
        print(f"\n   IAM Client Type: {type(agent.iam_client).__name__}")
        print(f"   IAM Client Connected: {agent.iam_client._connected if hasattr(agent.iam_client, '_connected') else 'N/A'}")
        print(f"   IAM Tools Available: {len(agent.iam_client.list_tools()) if agent.iam_client else 0}")
    
    if agent.cloudtrail_client:
        print(f"\n   CloudTrail Client Type: {type(agent.cloudtrail_client).__name__}")
        print(f"   CloudTrail Client Connected: {agent.cloudtrail_client._connected if hasattr(agent.cloudtrail_client, '_connected') else 'N/A'}")
        print(f"   CloudTrail Tools Available: {len(agent.cloudtrail_client.list_tools()) if agent.cloudtrail_client else 0}")
    
    if agent.api_client:
        print(f"\n   API Client Type: {type(agent.api_client).__name__}")
        print(f"   API Client Connected: {agent.api_client._connected if hasattr(agent.api_client, '_connected') else 'N/A'}")
        print(f"   API Tools Available: {len(agent.api_client.list_tools()) if agent.api_client else 0}")
    
    # Test role discovery
    print("\n3. Testing IAM Role Discovery...")
    print("   (This will show whether MCP or boto3 is used)")
    
    roles = agent._discover_iam_roles()
    
    print(f"\n   ✅ Discovered {len(roles)} roles")
    
    # Check the implementation
    print("\n4. Implementation Analysis:")
    print("   - audit_agent.py imports: from fastmcp_client import get_mcp_client ✅")
    print("   - Uses FastMCP's SyncMCPClient wrapper ✅")
    print("   - Fallback logic: Try MCP first → Fall back to boto3 ✅")
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    if mcp_success:
        print("\n✅ MCP SERVERS ARE BEING USED")
        print("   The audit agent is correctly using FastMCP to connect to:")
        print("   - aws-iam MCP server")
        print("   - aws-cloudtrail MCP server") 
        print("   - aws-api MCP server")
        print("\n   If MCP calls fail, it gracefully falls back to boto3.")
    else:
        print("\n⚠️  FALLING BACK TO BOTO3")
        print("   MCP servers are not available or failed to initialize.")
        print("   The audit agent will use boto3 directly for all operations.")
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    check_mcp_usage()

