# agent/fastmcp_client.py
"""
FastMCP-based client for AWS MCP servers
Provides a clean, async interface to interact with AWS IAM, CloudTrail, and AWS API MCP servers
"""
import asyncio
import json
import logging
import os
from typing import Dict, Any, Optional, List
from fastmcp import Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FastMCPClient:
    """FastMCP-based client for AWS MCP servers"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize FastMCP client with configuration
        
        Args:
            config_path: Path to mcp-config.json. If None, uses default location.
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()
        self.client: Optional[Client] = None
        self._connected = False
    
    def _get_default_config_path(self) -> str:
        """Get default config path relative to this file"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(current_dir, 'mcp-config.json')
    
    def _load_config(self) -> Dict[str, Any]:
        """Load MCP configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"✅ Loaded MCP config from {self.config_path}")
            logger.info(f"   Available servers: {list(config['mcpServers'].keys())}")
            return config
        except Exception as e:
            logger.error(f"❌ Failed to load MCP config: {e}")
            raise
    
    def _transform_config_for_fastmcp(self) -> Dict[str, Any]:
        """
        Transform mcp-config.json format to FastMCP client format
        
        Original format:
        {
          "mcpServers": {
            "aws-iam": {
              "command": "python",
              "args": ["-m", "awslabs.iam_mcp_server.server"],
              "env": {...}
            }
          }
        }
        
        FastMCP format:
        {
          "mcpServers": {
            "aws-iam": {
              "transport": "stdio",
              "command": "python",
              "args": ["-m", "awslabs.iam_mcp_server.server"],
              "env": {...}
            }
          }
        }
        """
        transformed = {"mcpServers": {}}
        
        for server_name, server_config in self.config['mcpServers'].items():
            # Add transport type (stdio for local Python servers)
            transformed_config = {
                "transport": "stdio",
                **server_config
            }
            transformed['mcpServers'][server_name] = transformed_config
        
        return transformed
    
    async def connect(self) -> bool:
        """
        Connect to all configured MCP servers
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            logger.info("🚀 Connecting to MCP servers...")
            
            # Transform config to FastMCP format
            fastmcp_config = self._transform_config_for_fastmcp()
            
            # Create FastMCP client with multi-server config
            self.client = Client(fastmcp_config)
            
            # Connect using async context manager pattern
            await self.client.__aenter__()
            self._connected = True
            
            logger.info("✅ Successfully connected to MCP servers")
            
            # List available tools from all servers
            await self._list_all_tools()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to MCP servers: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from all MCP servers"""
        if self.client and self._connected:
            try:
                await self.client.__aexit__(None, None, None)
                self._connected = False
                logger.info("🛑 Disconnected from MCP servers")
            except Exception as e:
                logger.error(f"❌ Error during disconnect: {e}")
    
    async def _list_all_tools(self):
        """List all available tools from all connected servers"""
        if not self.client or not self._connected:
            logger.warning("⚠️ Not connected to MCP servers")
            return
        
        try:
            tools = await self.client.list_tools()
            logger.info(f"📋 Available tools across all servers:")
            for tool in tools:
                logger.info(f"   - {tool.name}: {tool.description}")
        except Exception as e:
            logger.error(f"❌ Failed to list tools: {e}")
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call an MCP tool
        
        For multi-server setup, FastMCP automatically prefixes tool names with server name.
        Example: "aws-iam_analyze_policy", "aws-cloudtrail_query_events"
        
        Args:
            tool_name: Name of the tool (with or without server prefix)
            arguments: Tool arguments
        
        Returns:
            Dict with 'success' and 'data' or 'error'
        """
        if not self.client or not self._connected:
            return {
                "success": False,
                "error": "Not connected to MCP servers"
            }
        
        try:
            logger.info(f"🔧 Calling tool: {tool_name}")
            logger.debug(f"   Arguments: {arguments}")
            
            result = await self.client.call_tool(tool_name, arguments)
            
            # DEBUG: Log raw result before conversion
            logger.warning(f"🔍 [RAW] FastMCP result type: {type(result)}")
            logger.warning(f"🔍 [RAW] FastMCP result attributes: content={hasattr(result, 'content')}, data={hasattr(result, 'data')}, structured_content={hasattr(result, 'structured_content')}")
            
            # Check content first (MCP standard format)
            if hasattr(result, 'content'):
                logger.warning(f"🔍 [RAW] result.content type: {type(result.content)}, length: {len(result.content) if hasattr(result.content, '__len__') else 'N/A'}")
                if result.content:
                    logger.warning(f"🔍 [RAW] result.content[0] type: {type(result.content[0])}")
                    if hasattr(result.content[0], 'text'):
                        logger.warning(f"🔍 [RAW] result.content[0].text preview: {str(result.content[0].text)[:500]}")
            
            if hasattr(result, 'data'):
                logger.warning(f"🔍 [RAW] result.data type: {type(result.data)}")
                if hasattr(result.data, '__dict__'):
                    logger.warning(f"🔍 [RAW] result.data.__dict__ keys: {list(result.data.__dict__.keys())}")
                    logger.warning(f"🔍 [RAW] result.data.__dict__ values: {str(result.data.__dict__)[:800]}")
            
            # FastMCP returns data in TWO formats:
            # 1. result.content - MCP standard format (list of TextContent/Resource objects)
            # 2. result.data - Structured Pydantic models
            # We should check BOTH, but prefer content if available (it's the MCP standard)
            
            # Define conversion function first (needed for content items that might be Pydantic)
            def convert_pydantic_to_dict(obj):
                """Recursively convert Pydantic models to dicts"""
                if hasattr(obj, 'model_dump'):
                    # Pydantic v2 - convert and recurse on values
                    data = obj.model_dump()
                    # Recursively convert nested Pydantic objects
                    return convert_nested_models(data)
                elif hasattr(obj, 'dict'):
                    # Pydantic v1 - convert and recurse on values
                    data = obj.dict()
                    return convert_nested_models(data)
                elif hasattr(obj, '__dict__') and not isinstance(obj, (dict, list, str, int, float, bool, type(None))):
                    # Regular object - convert to dict
                    data = vars(obj)
                    return convert_nested_models(data)
                return obj
            
            def convert_nested_models(data):
                """Recursively convert nested Pydantic models in dicts/lists"""
                if isinstance(data, dict):
                    return {k: convert_pydantic_to_dict(v) for k, v in data.items()}
                elif isinstance(data, list):
                    return [convert_pydantic_to_dict(item) for item in data]
                elif hasattr(data, 'model_dump') or hasattr(data, 'dict'):
                    # Another Pydantic model
                    return convert_pydantic_to_dict(data)
                return data
            
            # Try content first (MCP standard format)
            if hasattr(result, 'content') and result.content:
                # Use MCP content format - convert content items to dict format
                content_list = []
                for item in result.content:
                    if hasattr(item, 'text'):
                        # TextContent object - extract text
                        content_list.append({'text': item.text})
                    elif hasattr(item, 'model_dump') or hasattr(item, 'dict'):
                        # Pydantic model in content
                        content_list.append(convert_pydantic_to_dict(item))
                    elif isinstance(item, dict):
                        content_list.append(item)
                    else:
                        # Try to convert to string or dict
                        if hasattr(item, '__dict__'):
                            content_list.append(vars(item))
                        else:
                            content_list.append({'text': str(item)})
                
                tool_result_data = {'content': content_list}
                logger.warning(f"🔍 [RAW] Using result.content format (MCP standard) - {len(content_list)} items")
                # Content is already converted, skip additional Pydantic conversion
            else:
                # Fall back to structured data - needs Pydantic conversion
                tool_result_data = result.data if hasattr(result, 'data') else result
                logger.warning(f"🔍 [RAW] Using result.data format (structured)")
                # Convert Pydantic models
                tool_result_data = convert_pydantic_to_dict(tool_result_data)
            
            logger.info(f"✅ Tool {tool_name} executed successfully")
            return {
                "success": True,
                "data": tool_result_data
            }
            
        except Exception as e:
            logger.error(f"❌ Tool call failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """
        List all available tools from all servers
        
        Returns:
            List of tool definitions
        """
        if not self.client or not self._connected:
            logger.warning("⚠️ Not connected to MCP servers")
            return []
        
        try:
            tools = await self.client.list_tools()
            return [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema if hasattr(tool, 'inputSchema') else {}
                }
                for tool in tools
            ]
        except Exception as e:
            logger.error(f"❌ Failed to list tools: {e}")
            return []
    
    async def list_resources(self) -> List[Dict[str, Any]]:
        """
        List all available resources from all servers
        
        Returns:
            List of resource definitions
        """
        if not self.client or not self._connected:
            logger.warning("⚠️ Not connected to MCP servers")
            return []
        
        try:
            resources = await self.client.list_resources()
            return [
                {
                    "uri": resource.uri,
                    "name": resource.name,
                    "description": resource.description if hasattr(resource, 'description') else ""
                }
                for resource in resources
            ]
        except Exception as e:
            logger.error(f"❌ Failed to list resources: {e}")
            return []
    
    async def read_resource(self, uri: str) -> Optional[str]:
        """
        Read a resource by URI
        
        Args:
            uri: Resource URI (e.g., "aws-iam://policies/list")
        
        Returns:
            Resource content as string, or None if failed
        """
        if not self.client or not self._connected:
            logger.warning("⚠️ Not connected to MCP servers")
            return None
        
        try:
            logger.info(f"📖 Reading resource: {uri}")
            content = await self.client.read_resource(uri)
            
            # Extract text from first content item
            if content and len(content) > 0:
                return content[0].text
            return None
            
        except Exception as e:
            logger.error(f"❌ Failed to read resource: {e}")
            return None
    
    async def ping(self) -> bool:
        """
        Check if servers are reachable
        
        Returns:
            bool: True if servers respond, False otherwise
        """
        if not self.client or not self._connected:
            return False
        
        try:
            await self.client.ping()
            logger.info("✅ MCP servers are reachable")
            return True
        except Exception as e:
            logger.error(f"❌ Ping failed: {e}")
            return False
    
    @property
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self._connected


# Global FastMCP client instance
_fastmcp_client: Optional[FastMCPClient] = None


async def get_fastmcp_client() -> Optional[FastMCPClient]:
    """
    Get or create global FastMCP client instance
    
    Returns:
        FastMCPClient instance or None if initialization failed
    """
    global _fastmcp_client
    
    if _fastmcp_client is None:
        _fastmcp_client = FastMCPClient()
        if not await _fastmcp_client.connect():
            _fastmcp_client = None
            return None
    
    return _fastmcp_client


async def close_fastmcp_client():
    """Close global FastMCP client"""
    global _fastmcp_client
    
    if _fastmcp_client:
        await _fastmcp_client.disconnect()
        _fastmcp_client = None


# Example usage
if __name__ == "__main__":
    async def main():
        # Create client
        client = FastMCPClient()
        
        # Connect to servers
        if await client.connect():
            # List available tools
            tools = await client.list_tools()
            print(f"\nAvailable tools: {len(tools)}")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")
            
            # Example: Call IAM policy analysis tool
            # result = await client.call_tool(
            #     "aws-iam_analyze_policy",
            #     {"policy_document": {...}}
            # )
            # print(f"\nResult: {result}")
            
            # Disconnect
            await client.disconnect()
    
    asyncio.run(main())


# ============================================================================
# SYNCHRONOUS WRAPPER FOR COMPATIBILITY WITH EXISTING CODE
# ============================================================================
# The existing audit_agent.py and validator_agent.py use synchronous code.
# These wrapper functions allow them to use FastMCP without rewriting everything.

import threading
from concurrent.futures import ThreadPoolExecutor

# Import nest_asyncio to allow nested event loops (needed for FastAPI)
try:
    import nest_asyncio
    nest_asyncio.apply()
    logger.info("✅ nest_asyncio applied - nested event loops enabled")
except ImportError:
    logger.warning("⚠️ nest_asyncio not installed - may have issues with FastAPI")
    logger.warning("   Install with: pip install nest-asyncio")

# Thread-local storage for event loop
_thread_local = threading.local()

def _get_or_create_event_loop():
    """Get or create event loop for current thread"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop

def _run_async(coro):
    """Run async coroutine in sync context"""
    loop = _get_or_create_event_loop()
    
    # Check if loop is already running (e.g., inside FastAPI)
    if loop.is_running():
        # nest_asyncio allows this to work
        return loop.run_until_complete(coro)
    else:
        return loop.run_until_complete(coro)


class SyncMCPClient:
    """
    Synchronous wrapper for FastMCPClient.
    Provides the same interface as the old mcp_client.py for backward compatibility.
    """
    
    def __init__(self, server_name: str):
        """
        Initialize sync MCP client for a specific server.
        Note: FastMCP connects to ALL servers, so we just store the server name prefix.
        
        Args:
            server_name: Server name (e.g., 'aws-iam', 'aws-cloudtrail', 'aws-api')
        """
        self.server_name = server_name
        self._async_client: Optional[FastMCPClient] = None
        self._connected = False
    
    def start(self) -> bool:
        """Start the MCP client (connects to all servers)"""
        try:
            self._async_client = FastMCPClient()
            self._connected = _run_async(self._async_client.connect())
            return self._connected
        except Exception as e:
            logger.error(f"❌ Failed to start sync MCP client: {e}")
            return False
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call an MCP tool synchronously.
        
        Args:
            tool_name: Tool name WITHOUT server prefix (e.g., 'list_roles', not 'aws-iam_list_roles')
            arguments: Tool arguments
        
        Returns:
            Dict with 'success' and 'data' or 'error'
        """
        if not self._async_client or not self._connected:
            return {
                "success": False,
                "error": "MCP client not connected"
            }
        
        try:
            # Add server prefix to tool name for FastMCP multi-server setup
            prefixed_tool_name = f"{self.server_name}_{tool_name}"
            result = _run_async(self._async_client.call_tool(prefixed_tool_name, arguments))
            return result
        except Exception as e:
            logger.error(f"❌ Sync tool call failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools for this server"""
        if not self._async_client or not self._connected:
            return []
        
        try:
            all_tools = _run_async(self._async_client.list_tools())
            # Filter tools for this specific server
            server_tools = [
                tool for tool in all_tools
                if tool['name'].startswith(f"{self.server_name}_")
            ]
            # Remove server prefix from tool names for compatibility
            for tool in server_tools:
                tool['name'] = tool['name'].replace(f"{self.server_name}_", "")
            return server_tools
        except Exception as e:
            logger.error(f"❌ Failed to list tools: {e}")
            return []
    
    def close(self):
        """Close the MCP client"""
        if self._async_client and self._connected:
            try:
                _run_async(self._async_client.disconnect())
                self._connected = False
            except Exception as e:
                logger.error(f"❌ Error closing sync client: {e}")


# Global sync MCP clients (for backward compatibility)
_sync_mcp_clients: Dict[str, SyncMCPClient] = {}


def get_mcp_client(server_name: str) -> Optional[SyncMCPClient]:
    """
    Get or create synchronous MCP client for a server.
    This function provides backward compatibility with the old mcp_client.py.
    
    Args:
        server_name: Server name (e.g., 'aws-iam', 'aws-cloudtrail', 'aws-api')
    
    Returns:
        SyncMCPClient instance or None if initialization failed
    """
    global _sync_mcp_clients
    
    # Return existing client if already initialized
    if server_name in _sync_mcp_clients:
        return _sync_mcp_clients[server_name]
    
    # Create new sync client
    try:
        client = SyncMCPClient(server_name)
        if client.start():
            _sync_mcp_clients[server_name] = client
            logger.info(f"✅ Sync MCP client for {server_name} initialized")
            return client
        else:
            logger.error(f"❌ Failed to initialize sync MCP client for {server_name}")
            return None
    except Exception as e:
        logger.error(f"❌ Error creating sync MCP client: {e}")
        return None


def close_all_mcp_clients():
    """Close all sync MCP clients"""
    global _sync_mcp_clients
    
    for client in _sync_mcp_clients.values():
        client.close()
    
    _sync_mcp_clients.clear()
    logger.info("🛑 All sync MCP clients closed")


# Example usage
if __name__ == "__main__":
    # Async example
    async def async_example():
        client = FastMCPClient()
        
        if await client.connect():
            tools = await client.list_tools()
            print(f"\nAvailable tools: {len(tools)}")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")
            
            await client.disconnect()
    
    # Sync example (backward compatible)
    def sync_example():
        # This works exactly like the old mcp_client.py
        client = get_mcp_client('aws-iam')
        
        if client:
            tools = client.list_tools()
            print(f"\nIAM Tools: {len(tools)}")
            for tool in tools:
                print(f"  - {tool['name']}")
            
            # Call a tool
            result = client.call_tool('list_roles', {})
            print(f"\nResult: {result}")
            
            close_all_mcp_clients()
    
    # Run sync example (compatible with existing code)
    print("\n=== Synchronous Example (Backward Compatible) ===")
    sync_example()
    
    # Run async example
    print("\n=== Asynchronous Example (New FastMCP) ===")
    asyncio.run(async_example())