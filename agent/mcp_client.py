# agent/mcp_client.py
"""
Proper MCP client that communicates with AWS MCP servers via stdio
"""
import subprocess
import json
import logging
import os
from typing import Dict, Any, Optional, List

logging.basicConfig(level=logging.INFO)

class MCPClient:
    """Client for AWS MCP servers using stdio JSON-RPC protocol"""
    
    def __init__(self, server_config: Dict[str, Any]):
        self.command = server_config['command']
        self.args = server_config['args']
        self.env = {**os.environ, **server_config.get('env', {})}
        self.process: Optional[subprocess.Popen] = None
        self.request_id = 0
        
    def start(self) -> bool:
        """Start the MCP server process"""
        try:
            logging.info(f"🚀 Starting MCP server: {self.command} {' '.join(self.args)}")
            
            self.process = subprocess.Popen(
                [self.command] + self.args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
                text=True,
                bufsize=1
            )
            
            # Initialize MCP protocol
            init_response = self._send_request({
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "clientInfo": {
                        "name": "aegis-iam",
                        "version": "1.0.0"
                    }
                }
            })
            
            if init_response and 'result' in init_response:
                logging.info(f"✅ MCP server initialized successfully")
                logging.info(f"   Server capabilities: {init_response['result'].get('capabilities', {})}")
                return True
            else:
                logging.error(f"❌ MCP initialization failed: {init_response}")
                return False
                
        except Exception as e:
            logging.error(f"❌ Failed to start MCP server: {e}")
            return False
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool"""
        try:
            logging.info(f"🔧 Calling MCP tool: {tool_name} with args: {arguments}")
            
            response = self._send_request({
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            })
            
            if response and 'result' in response:
                logging.info(f"✅ MCP tool {tool_name} succeeded")
                return {
                    "success": True,
                    "data": response['result']
                }
            elif response and 'error' in response:
                logging.error(f"❌ MCP tool {tool_name} error: {response['error']}")
                return {
                    "success": False,
                    "error": response['error']['message']
                }
            else:
                logging.error(f"❌ Unexpected MCP response: {response}")
                return {
                    "success": False,
                    "error": "Unexpected response format"
                }
                
        except Exception as e:
            logging.error(f"❌ MCP tool call failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List available MCP tools"""
        try:
            response = self._send_request({
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/list"
            })
            
            if response and 'result' in response:
                tools = response['result'].get('tools', [])
                logging.info(f"📋 Available MCP tools: {[t['name'] for t in tools]}")
                return tools
            else:
                return []
                
        except Exception as e:
            logging.error(f"❌ Failed to list tools: {e}")
            return []
    
    def _send_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send JSON-RPC request and get response"""
        if not self.process or self.process.poll() is not None:
            logging.error("❌ MCP server process not running")
            return None
        
        try:
            # Send request
            request_json = json.dumps(request) + '\n'
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            # Read response
            response_line = self.process.stdout.readline()
            if not response_line:
                return None
            
            response = json.loads(response_line.strip())
            return response
            
        except Exception as e:
            logging.error(f"❌ Communication error: {e}")
            return None
    
    def _next_id(self) -> int:
        """Generate next request ID"""
        self.request_id += 1
        return self.request_id
    
    def close(self):
        """Shutdown MCP server"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            logging.info("🛑 MCP server stopped")


# Global MCP clients
_mcp_clients: Dict[str, MCPClient] = {}

def get_mcp_client(server_name: str) -> Optional[MCPClient]:
    """Get or create MCP client for a server"""
    global _mcp_clients
    
    if server_name in _mcp_clients:
        return _mcp_clients[server_name]
    
    # Load MCP config
    try:
        import os
        import json
        
        # Get config path relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_dir, 'mcp-config.json')
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        if server_name not in config['mcpServers']:
            logging.error(f"❌ MCP server {server_name} not found in config")
            return None
        
        client = MCPClient(config['mcpServers'][server_name])
        if client.start():
            _mcp_clients[server_name] = client
            return client
        else:
            return None
            
    except Exception as e:
        logging.error(f"❌ Failed to initialize MCP client: {e}")
        return None