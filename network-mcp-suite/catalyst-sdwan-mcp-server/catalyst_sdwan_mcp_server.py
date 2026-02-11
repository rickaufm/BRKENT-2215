#!/usr/bin/env python3
"""
Cisco Catalyst SD-WAN MCP Server

A Model Context Protocol (MCP) server that provides comprehensive access to Cisco Catalyst SD-WAN (formerly Viptela) 
API functionality. This server allows AI assistants and other MCP clients to interact with Cisco SD-WAN Manager 
for network monitoring, device management, and software version analysis.

Features:
- Software version inventory and analysis across SD-WAN fabric
- Device inventory with detailed information (controllers and routers)
- Version compliance checking and reporting
- Device health monitoring (CPU, memory, disk, uptime)
- Control connections monitoring
- BFD sessions monitoring
- Interface statistics and IP information
- Real-time BGP monitoring
- Real-time OMP monitoring
- Configuration groups and device associations
- Application health monitoring by site
- Network Wide Path Insight (NWPI) trace and analysis
- QoS policer configuration retrieval and updates
- Support for vManage, vSmart, vBond (controllers) and vEdge, cEdge (routers)
- Real-time device status and health monitoring

Environment Variables:
- VMANAGE_USERNAME: Required. Your vManage username with API access
- VMANAGE_PASSWORD: Required. Your vManage password
- VMANAGE_HOST: Required. Your vManage hostname or IP
- VMANAGE_PORT: Optional. vManage port. Defaults to 443
- VMANAGE_VERIFY_SSL: Optional. SSL verification. Defaults to False
- MCP_PORT: Optional. Port for MCP server. Defaults to 8007
- MCP_HOST: Optional. Host for MCP server. Defaults to localhost

Author: Ricardo Kaufmann
Based on: Cisco Catalyst SD-WAN API
"""

import os
import sys
import json
import logging
import httpx
import urllib3
import tarfile
import io
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter
from datetime import datetime, timezone
from fastmcp import FastMCP

# Disable SSL warnings if verify is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("catalyst-sdwan-server")

# ---- Environment Variables ----
def load_dotenv_file(env_file: str = ".env") -> bool:
    """Load environment variables from a .env file"""
    env_path = Path(env_file)
    
    if not env_path.exists():
        print(f"⚠️  .env file not found at {env_path.absolute()}")
        print(f"📋 Using environment variables or defaults")
        return False
    
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip().strip('\'"')
                    os.environ[key.strip()] = value
        print(f"✅ Loaded environment variables from {env_path}")
        return True
    except Exception as e:
        print(f"❌ Error loading .env file: {e}")
        return False

# Load environment variables
load_dotenv_file()

# Configuration
VMANAGE_USERNAME = os.getenv("VMANAGE_USERNAME")
VMANAGE_PASSWORD = os.getenv("VMANAGE_PASSWORD")
VMANAGE_HOST = os.getenv("VMANAGE_HOST")
VMANAGE_PORT = os.getenv("VMANAGE_PORT", "443")
VMANAGE_VERIFY_SSL = os.getenv("VMANAGE_VERIFY_SSL", "False").lower() == "true"
mcp_host = os.getenv("MCP_HOST", "localhost")
mcp_port = int(os.getenv("MCP_PORT", "8007"))

# Validate required environment variables
if not all([VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_HOST]):
    raise ValueError("VMANAGE_USERNAME, VMANAGE_PASSWORD, and VMANAGE_HOST environment variables are required")

print(f"🌐 vManage Server: {VMANAGE_HOST}:{VMANAGE_PORT}")
print(f"👤 vManage User: {VMANAGE_USERNAME}")
print(f"🔐 SSL Verification: {VMANAGE_VERIFY_SSL}")
print(f"🚀 Starting MCP server on {mcp_host}:{mcp_port}")

class CiscoSDWANAPI:
    """Cisco Catalyst SD-WAN REST API client"""
    
    def __init__(self, host: str, port: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}:{self.port}"
        
        self.jsessionid = None
        self.xsrf_token = None
        
        logger.info(f"Initialized SD-WAN API client for {self.host}:{self.port}")
    
    async def authenticate(self) -> Tuple[str, str]:
        """Authenticate with vManage and return session ID and XSRF token."""
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            # Step 1: Get JSESSIONID
            login_url = f"{self.base_url}/j_security_check"
            payload = {
                'j_username': self.username,
                'j_password': self.password
            }
            
            logger.info(f"Authenticating with vManage at {self.host}:{self.port}")
            response = await client.post(
                login_url, 
                data=payload,
                follow_redirects=False
            )
            
            # Extract JSESSIONID from cookies
            cookies = response.cookies
            jsessionid = None
            for key, value in cookies.items():
                if key == "JSESSIONID":
                    jsessionid = value
                    break
            
            if not jsessionid:
                # Check Set-Cookie header as fallback
                set_cookie = response.headers.get("Set-Cookie", "")
                if "JSESSIONID=" in set_cookie:
                    jsessionid = set_cookie.split("JSESSIONID=")[1].split(";")[0]
            
            if not jsessionid:
                raise Exception("Failed to get JSESSIONID - invalid credentials")
            
            # Step 2: Get XSRF Token
            token_url = f"{self.base_url}/dataservice/client/token"
            headers = {'Cookie': f'JSESSIONID={jsessionid}'}
            
            response = await client.get(token_url, headers=headers)
            if response.status_code == 200:
                xsrf_token = response.text.strip()
                logger.info("Successfully authenticated with vManage")
                self.jsessionid = jsessionid
                self.xsrf_token = xsrf_token
                return jsessionid, xsrf_token
            else:
                raise Exception(f"Failed to get XSRF token: {response.status_code}")
    
    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get list of all devices from vManage."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info("Fetching device list from vManage")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                devices = data.get('data', [])
                logger.info(f"Retrieved {len(devices)} devices")
                return devices
            else:
                raise Exception(f"Failed to get devices: {response.status_code} - {response.text}")
    
    async def get_device_health(self, device_id: str) -> Dict[str, Any]:
        """Get system health status for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/system/status?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching health status for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get device health: {response.status_code} - {response.text}")
    
    async def get_control_connections(self, device_id: str) -> Dict[str, Any]:
        """Get control connections for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/control/connections?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching control connections for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get control connections: {response.status_code} - {response.text}")
    
    async def get_bfd_sessions(self, device_id: str) -> Dict[str, Any]:
        """Get BFD sessions for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/bfd/sessions?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching BFD sessions for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get BFD sessions: {response.status_code} - {response.text}")
    
    async def get_interfaces(self, device_id: str) -> Dict[str, Any]:
        """Get interface information and statistics for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/interface?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching interfaces for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get interfaces: {response.status_code} - {response.text}")
    
    async def get_bgp_neighbors(self, device_id: str) -> Dict[str, Any]:
        """Get BGP neighbors for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/bgp/neighbors?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching BGP neighbors for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get BGP neighbors: {response.status_code} - {response.text}")
    
    async def get_bgp_summary(self, device_id: str) -> Dict[str, Any]:
        """Get BGP summary for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/bgp/summary?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching BGP summary for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get BGP summary: {response.status_code} - {response.text}")
    
    async def get_omp_peers(self, device_id: str) -> Dict[str, Any]:
        """Get OMP peers for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/peers?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP peers for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP peers: {response.status_code} - {response.text}")
    
    async def get_omp_summary(self, device_id: str) -> Dict[str, Any]:
        """Get OMP summary for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/summary?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP summary for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP summary: {response.status_code} - {response.text}")
    
    async def get_bgp_routes(self, device_id: str) -> Dict[str, Any]:
        """Get BGP routes for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/bgp/routes?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching BGP routes for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get BGP routes: {response.status_code} - {response.text}")
    
    async def get_omp_routes_received(self, device_id: str) -> Dict[str, Any]:
        """Get OMP routes received for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/routes/received?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP routes received for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP routes received: {response.status_code} - {response.text}")
    
    async def get_omp_routes_advertised(self, device_id: str) -> Dict[str, Any]:
        """Get OMP routes advertised (sent) for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/routes/advertised?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP routes advertised for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP routes advertised: {response.status_code} - {response.text}")
    
    async def get_omp_tlocs_received(self, device_id: str) -> Dict[str, Any]:
        """Get OMP TLOCs received for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/tlocs/received?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP TLOCs received for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP TLOCs received: {response.status_code} - {response.text}")
    
    async def get_omp_tlocs_advertised(self, device_id: str) -> Dict[str, Any]:
        """Get OMP TLOCs advertised (sent) for a specific device."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/device/omp/tlocs/advertised?deviceId={device_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching OMP TLOCs advertised for device {device_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get OMP TLOCs advertised: {response.status_code} - {response.text}")
    
    async def get_configuration_groups(self) -> List[Dict[str, Any]]:
        """Get all configuration groups."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/v1/config-group"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info("Fetching configuration groups")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                # Handle both list and dict responses
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get('data', [])
                else:
                    return []
            else:
                raise Exception(f"Failed to get configuration groups: {response.status_code} - {response.text}")
    
    async def get_application_health_by_site(self, site_id: str) -> List[Dict[str, Any]]:
        """Get application health statistics for a specific site."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        # Use siteid parameter (lowercase, no hyphen)
        url = f"{self.base_url}/dataservice/statistics/perfmon/applications/site/health?siteid={site_id}"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching application health for site {site_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to get application health: {response.status_code} - {response.text}")
    
    async def start_nwpi_trace(self, site_id: str) -> Dict[str, Any]:
        """Start a Network Wide Path Insight trace for a specific site."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/stream/device/nwpi/trace/start"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }
        
        payload = {
            "source-site": str(site_id),
            "duration": "1",
            "local-drop-rate-threshold": 5,
            "wan-drop-rate-threshold": 5,
            "vpn-id": "all",
            "art-vis": "true",
            "app-vis": "true",
            "qos-mon": "true",
            "source-site-version": "17.15",
            "traceModel": "SDWAN_MANUAL",
            "warning": ""
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=60.0) as client:
            logger.info(f"Starting NWPI trace for site {site_id}")
            response = await client.post(url, headers=headers, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"NWPI trace started successfully with trace-id: {data.get('trace-id')}")
                return data
            else:
                raise Exception(f"Failed to start NWPI trace: {response.status_code} - {response.text}")
    
    async def export_nwpi_trace(self, trace_id: str, timestamp: str) -> bytes:
        """Export a Network Wide Path Insight trace as tar.gz file."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()
        
        url = f"{self.base_url}/dataservice/stream/device/nwpi/exportTrace?traceId={trace_id}&timestamp={timestamp}&traceModel=SDWAN_MANUAL"
        
        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token
        }
        
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=120.0) as client:
            logger.info(f"Exporting NWPI trace {trace_id}")
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                logger.info(f"NWPI trace exported successfully")
                return response.content
            else:
                raise Exception(f"Failed to export NWPI trace: {response.status_code} - {response.text}")

    async def get_policy_groups(self) -> List[Dict[str, Any]]:
        """Get list of all policy groups."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/policy-group?solution=sdwan"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info("Fetching policy groups from vManage")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                # Handle both response formats: wrapped in 'data' or direct list
                if isinstance(data, list):
                    policy_groups = data
                elif isinstance(data, dict) and 'data' in data:
                    policy_groups = data.get('data', [])
                else:
                    policy_groups = []
                logger.info(f"Retrieved {len(policy_groups)} policy groups")
                return policy_groups
            else:
                raise Exception(f"Failed to get policy groups: {response.status_code} - {response.text}")

    async def get_policy_group_device_associations(self, policy_group_id: str) -> List[Dict[str, Any]]:
        """Get device associations for a specific policy group."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/policy-group/{policy_group_id}/device/associate"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching device associations for policy group {policy_group_id}")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"API Response type: {type(data)}")
                logger.info(f"API Response keys: {data.keys() if isinstance(data, dict) else 'N/A'}")

                # Handle multiple response formats
                if isinstance(data, list):
                    associations = data
                elif isinstance(data, dict):
                    # Try 'devices' first (policy group associations), then 'data'
                    associations = data.get('devices', data.get('data', []))
                else:
                    associations = []

                logger.info(f"Retrieved {len(associations)} device associations")
                if associations and len(associations) > 0:
                    logger.info(f"First device keys: {list(associations[0].keys())}")
                    logger.info(f"First device deviceIP: {associations[0].get('deviceIP')}")

                return associations
            else:
                raise Exception(f"Failed to get policy group device associations: {response.status_code} - {response.text}")

    async def get_policy_group_details(self, policy_group_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific policy group."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/policy-group/{policy_group_id}"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching policy group details for {policy_group_id}")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Retrieved policy group details")
                return data
            else:
                raise Exception(f"Failed to get policy group details: {response.status_code} - {response.text}")

    async def get_application_priority_profile(self, profile_id: str) -> Dict[str, Any]:
        """Get application-priority profile details."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/feature-profile/sdwan/application-priority/{profile_id}"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching application-priority profile {profile_id}")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Retrieved application-priority profile")
                return data
            else:
                raise Exception(f"Failed to get application-priority profile: {response.status_code} - {response.text}")

    async def get_qos_policy_details(self, profile_id: str, qos_policy_id: str) -> Dict[str, Any]:
        """Get QoS policy (policer) details."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/feature-profile/sdwan/application-priority/{profile_id}/qos-policy/{qos_policy_id}"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching QoS policy {qos_policy_id} from profile {profile_id}")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Retrieved QoS policy details")
                return data
            else:
                raise Exception(f"Failed to get QoS policy details: {response.status_code} - {response.text}")

    async def get_policy_object_profiles(self) -> List[Dict[str, Any]]:
        """Get list of all policy object profiles."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/feature-profile/sdwan/policy-object"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Fetching policy object profiles")
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Retrieved policy object profiles")
                # Handle both list and dict responses
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get('data', [])
                return []
            else:
                raise Exception(f"Failed to get policy object profiles: {response.status_code} - {response.text}")

    async def update_policer_via_policy_object(self, policy_object_id: str, list_object_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update policer configuration via policy-object endpoint."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/feature-profile/sdwan/policy-object/{policy_object_id}/policer/{list_object_id}"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Updating policer {list_object_id} in policy object {policy_object_id}")
            response = await client.put(url, json=payload, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully updated policer")
                return data
            else:
                raise Exception(f"Failed to update QoS policy: {response.status_code} - {response.text}")

    async def deploy_policy_group(self, policy_group_id: str, device_ids: List[str]) -> Dict[str, Any]:
        """Deploy policy group to selected devices."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/policy-group/{policy_group_id}/device/deploy"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        # Build the payload with device IDs
        payload = {
            "devices": [{"id": device_id} for device_id in device_ids]
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Deploying policy group {policy_group_id} to devices: {device_ids}")
            response = await client.post(url, json=payload, headers=headers)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully deployed policy group to devices")
                return data
            else:
                raise Exception(f"Failed to deploy policy group: {response.status_code} - {response.text}")

    async def update_qos_policy(self, profile_id: str, qos_policy_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update QoS policy (policer) configuration."""
        if not self.jsessionid or not self.xsrf_token:
            await self.authenticate()

        url = f"{self.base_url}/dataservice/v1/feature-profile/sdwan/application-priority/{profile_id}/qos-policy/{qos_policy_id}"

        headers = {
            'Cookie': f'JSESSIONID={self.jsessionid}',
            'X-XSRF-TOKEN': self.xsrf_token,
            'Content-Type': 'application/json'
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
            logger.info(f"Updating QoS policy {qos_policy_id} in profile {profile_id}")
            response = await client.put(url, headers=headers, json=payload)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully updated QoS policy")
                return data
            else:
                raise Exception(f"Failed to update QoS policy: {response.status_code} - {response.text}")

    def analyze_software_versions(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze software versions across all devices."""
        # Group devices by type
        controllers = []
        routers = []
        
        for device in devices:
            device_type = device.get('device-type', '').lower()
            personality = device.get('personality', '').lower()
            
            # Controllers include vManage, vSmart, vBond
            if personality in ['vmanage', 'vsmart', 'vbond'] or device_type in ['vmanage', 'vsmart', 'vbond']:
                controllers.append(device)
            # Routers include vEdge and cEdge devices
            elif personality in ['vedge', 'cedge'] or device_type in ['vedge', 'cedge'] or 'edge' in device_type.lower():
                routers.append(device)
        
        # Count versions for each group
        controller_versions = Counter()
        router_versions = Counter()
        all_versions = Counter()
        
        for device in controllers:
            version = device.get('version', 'Unknown')
            if version and version != 'Unknown':
                controller_versions[version] += 1
                all_versions[version] += 1
        
        for device in routers:
            version = device.get('version', 'Unknown')
            if version and version != 'Unknown':
                router_versions[version] += 1
                all_versions[version] += 1
        
        return {
            'total_devices': len(devices),
            'controller_count': len(controllers),
            'router_count': len(routers),
            'controller_versions': dict(controller_versions),
            'router_versions': dict(router_versions),
            'all_versions': dict(all_versions),
            'controllers': controllers,
            'routers': routers
        }
    
    @staticmethod
    def format_device_details(devices: List[Dict[str, Any]], device_type: str) -> str:
        """Format device details for display."""
        if not devices:
            return f"No {device_type} found"
        
        lines = []
        for device in devices:
            hostname = device.get('host-name', 'N/A')
            device_model = device.get('device-model', 'N/A')
            version = device.get('version', 'N/A')
            system_ip = device.get('system-ip', 'N/A')
            site_id = device.get('site-id', 'N/A')
            status = device.get('status', 'N/A')
            lines.append(f"  • {hostname} ({device_model}) - v{version} - IP: {system_ip} - Site: {site_id} - Status: {status}")
        
        return "\n".join(lines)

# Initialize SD-WAN API client
sdwan_api = CiscoSDWANAPI(VMANAGE_HOST, VMANAGE_PORT, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)

# Initialize FastMCP
mcp = FastMCP("Cisco Catalyst SD-WAN MCP Server")

# ---- MCP Tools ----

@mcp.tool()
async def get_software_versions(vmanage_url: Optional[str] = None) -> str:
    """
    Get software versions running on all SD-WAN devices and count by version
    
    Retrieves comprehensive software version information from the Catalyst SD-WAN fabric,
    including version distribution across controllers (vManage, vSmart, vBond) and 
    routers (vEdge, cEdge).
    
    Args:
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com' or 'vmanage.example.com:8443')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Total device count
        - Controller and router counts
        - Version distribution by device type
        - Percentage breakdown of all versions
    """
    logger.info(f"Executing get_software_versions with URL: {vmanage_url}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            # Parse URL if provided
            url = vmanage_url.strip()
            # Remove https:// or http:// if present
            url = url.replace("https://", "").replace("http://", "")
            # Split host and port if port is provided
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            
            # Create temporary API client
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        # Authenticate and get devices
        await api.authenticate()
        devices = await api.get_devices()
        
        # Analyze versions
        analysis = api.analyze_software_versions(devices)
        
        # Format output
        output = f"""✅ Software Version Analysis for Catalyst SD-WAN Network

📊 Summary:
- Total Devices: {analysis['total_devices']}
- Controllers: {analysis['controller_count']}
- Routers: {analysis['router_count']}

🔧 Controller Software Versions:"""
        
        if analysis['controller_versions']:
            for version, count in sorted(analysis['controller_versions'].items()):
                output += f"\n  • Version {version}: {count} device(s)"
        else:
            output += "\n  • No controllers found"
        
        output += "\n\n🌐 Router Software Versions:"
        if analysis['router_versions']:
            for version, count in sorted(analysis['router_versions'].items()):
                output += f"\n  • Version {version}: {count} device(s)"
        else:
            output += "\n  • No routers found"
        
        output += "\n\n📈 All Versions Combined:"
        if analysis['all_versions']:
            for version, count in sorted(analysis['all_versions'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / analysis['total_devices']) * 100
                output += f"\n  • Version {version}: {count} device(s) ({percentage:.1f}%)"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting software versions: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_device_details(
    vmanage_url: Optional[str] = None,
    show_details: bool = False
) -> str:
    """
    Get detailed information about all SD-WAN devices including hostname, model, version, and status
    
    Provides comprehensive inventory of all devices in the Catalyst SD-WAN fabric, including
    controllers and routers with their operational status, software versions, and network details.
    
    Args:
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com' or 'vmanage.example.com:8443')
                     If not provided, uses default from environment variables
        show_details: If True, shows detailed information for each device including hostname, model,
                      version, IP address, site ID, and status. Defaults to False for summary view.
    
    Returns:
        Formatted string containing:
        - Device inventory summary
        - Detailed device list (if show_details=True)
        - Device status and health information
    """
    logger.info(f"Executing get_device_details with URL: {vmanage_url}, show_details: {show_details}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            
            # Create temporary API client
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        # Authenticate and get devices
        await api.authenticate()
        devices = await api.get_devices()
        
        # Analyze devices
        analysis = api.analyze_software_versions(devices)
        
        # Format output
        output = f"""✅ Catalyst SD-WAN Device Inventory

📊 Summary:
- Total Devices: {analysis['total_devices']}
- Controllers: {analysis['controller_count']}
- Routers: {analysis['router_count']}"""
        
        # Show details if requested
        if show_details:
            output += "\n\n🔧 Controllers:"
            output += "\n" + api.format_device_details(analysis['controllers'], "controllers")
            
            output += "\n\n🌐 Routers:"
            output += "\n" + api.format_device_details(analysis['routers'], "routers")
        else:
            output += "\n\n💡 Set show_details=True to see individual device information"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting device details: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_version_compliance(
    target_version: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Check software version compliance and identify devices not on target version
    
    Analyzes the entire SD-WAN fabric to determine which devices are running the target
    software version and which devices need upgrades. Provides compliance percentage
    and detailed breakdown of non-compliant devices grouped by their current version.
    
    Args:
        target_version: Required. The target software version to check compliance against
                        (e.g., '20.12.1', '17.9.3a')
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com' or 'vmanage.example.com:8443')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Overall compliance percentage
        - List of compliant devices
        - List of non-compliant devices grouped by version
        - Upgrade recommendations
    """
    logger.info(f"Executing get_version_compliance with target version: {target_version}")
    
    try:
        if not target_version or not target_version.strip():
            return "❌ Error: target_version parameter is required"
        
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            
            # Create temporary API client
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        # Authenticate and get devices
        await api.authenticate()
        devices = await api.get_devices()
        
        # Check compliance
        compliant_devices = []
        non_compliant_devices = []
        
        for device in devices:
            version = device.get('version', 'Unknown')
            if version == target_version.strip():
                compliant_devices.append(device)
            else:
                non_compliant_devices.append(device)
        
        # Calculate compliance percentage
        total = len(devices)
        compliant_count = len(compliant_devices)
        compliance_percentage = (compliant_count / total * 100) if total > 0 else 0
        
        # Format output
        output = f"""✅ Version Compliance Report

📊 Target Version: {target_version}
- Total Devices: {total}
- Compliant: {compliant_count} ({compliance_percentage:.1f}%)
- Non-Compliant: {len(non_compliant_devices)} ({100-compliance_percentage:.1f}%)

✅ Compliant Devices ({compliant_count}):"""
        
        if compliant_devices:
            for device in compliant_devices:
                hostname = device.get('host-name', 'N/A')
                device_type = device.get('device-type', 'N/A')
                output += f"\n  • {hostname} ({device_type})"
        else:
            output += "\n  • None"
        
        output += f"\n\n⚠️ Non-Compliant Devices ({len(non_compliant_devices)}):"
        
        if non_compliant_devices:
            # Group by version
            version_groups = {}
            for device in non_compliant_devices:
                version = device.get('version', 'Unknown')
                if version not in version_groups:
                    version_groups[version] = []
                version_groups[version].append(device)
            
            for version, devices_list in sorted(version_groups.items()):
                output += f"\n  Version {version}:"
                for device in devices_list:
                    hostname = device.get('host-name', 'N/A')
                    device_type = device.get('device-type', 'N/A')
                    output += f"\n    • {hostname} ({device_type})"
        else:
            output += "\n  • None"
        
        return output
        
    except Exception as e:
        logger.error(f"Error checking version compliance: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_device_health(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get device health status including CPU, memory, disk usage, and uptime
    
    Retrieves comprehensive health metrics for either a specific device or all devices
    in the SD-WAN fabric. Health metrics include CPU utilization, memory usage, 
    disk space, system uptime, and reachability status.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns health for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Device hostname and system IP
        - Reachability status
        - CPU utilization percentage
        - Memory usage (used/available)
        - Disk usage percentage
        - System uptime
    """
    logger.info(f"Executing get_device_health for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get health for specific device
        if device_id and device_id.strip():
            health_data = await api.get_device_health(device_id.strip())
            
            if not health_data:
                return f"❌ No health data found for device {device_id}"
            
            output = f"""✅ Device Health Status

📊 Device: {device_id}"""
            
            for item in health_data:
                hostname = item.get('vdevice-host-name', 'N/A')
                reachability = item.get('reachability', 'N/A')
                status = item.get('status', 'N/A')
                cpu_load = item.get('cpu-load', 'N/A')
                mem_used = item.get('mem-used', 'N/A')
                mem_total = item.get('mem-total', 'N/A')
                disk_used = item.get('disk-used', 'N/A')
                disk_avail = item.get('disk-avail', 'N/A')
                uptime = item.get('uptime', 'N/A')
                
                output += f"""

🖥️  Hostname: {hostname}
📡 Reachability: {reachability}
🟢 Status: {status}
💻 CPU Load: {cpu_load}%
🧠 Memory: {mem_used}MB / {mem_total}MB
💾 Disk: {disk_used}% used ({disk_avail}MB available)
⏱️  Uptime: {uptime}"""
            
            return output
        
        # Otherwise, get health for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ Device Health Status - All Devices

📊 Total Devices: {len(devices)}
"""
            
            healthy_count = 0
            warning_count = 0
            critical_count = 0
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                status = device.get('status', 'N/A')
                reachability = device.get('reachability', 'N/A')
                
                try:
                    health_data = await api.get_device_health(device_id)
                    
                    if health_data:
                        for item in health_data:
                            cpu_load = float(item.get('cpu-load', 0))
                            mem_used = float(item.get('mem-used', 0))
                            mem_total = float(item.get('mem-total', 1))
                            mem_percent = (mem_used / mem_total * 100) if mem_total > 0 else 0
                            
                            # Determine health status
                            if cpu_load > 80 or mem_percent > 90:
                                status_icon = "🔴"
                                critical_count += 1
                            elif cpu_load > 60 or mem_percent > 75:
                                status_icon = "🟡"
                                warning_count += 1
                            else:
                                status_icon = "🟢"
                                healthy_count += 1
                            
                            output += f"\n{status_icon} {hostname} ({device_id}) - CPU: {cpu_load:.1f}% | Mem: {mem_percent:.1f}% | Status: {status}"
                except Exception as e:
                    output += f"\n⚠️  {hostname} ({device_id}) - Health data unavailable"
            
            output += f"""

📈 Health Summary:
🟢 Healthy: {healthy_count} devices
🟡 Warning: {warning_count} devices
🔴 Critical: {critical_count} devices"""
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting device health: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_control_connections(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get control plane connections status for SD-WAN devices
    
    Retrieves information about active control plane connections between edge devices
    and controllers (vSmart, vBond, vManage). Shows connection state, peer information,
    and connection uptime.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns control connections for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Device hostname and system IP
        - Connected controllers
        - Connection state (up/down)
        - Connection type and protocol
        - Uptime information
    """
    logger.info(f"Executing get_control_connections for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get connections for specific device
        if device_id and device_id.strip():
            connections_data = await api.get_control_connections(device_id.strip())
            
            if not connections_data:
                return f"❌ No control connection data found for device {device_id}"
            
            output = f"""✅ Control Plane Connections

📊 Device: {device_id}
🔗 Total Connections: {len(connections_data)}
"""
            
            for conn in connections_data:
                peer_type = conn.get('peer-type', 'N/A')
                peer_system_ip = conn.get('system-ip', 'N/A')
                state = conn.get('state', 'N/A')
                protocol = conn.get('protocol', 'N/A')
                uptime = conn.get('uptime', 'N/A')
                
                state_icon = "🟢" if state == "up" else "🔴"
                
                output += f"\n{state_icon} {peer_type} - {peer_system_ip}"
                output += f"\n   Protocol: {protocol} | State: {state} | Uptime: {uptime}"
            
            return output
        
        # Otherwise, get connections for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ Control Plane Connections - All Devices

📊 Total Devices: {len(devices)}
"""
            
            total_connections = 0
            devices_with_issues = []
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                
                try:
                    connections_data = await api.get_control_connections(device_id)
                    
                    if connections_data:
                        conn_count = len(connections_data)
                        total_connections += conn_count
                        
                        # Check for down connections
                        down_connections = [c for c in connections_data if c.get('state') != 'up']
                        
                        if down_connections:
                            output += f"\n⚠️  {hostname} ({device_id}) - {conn_count} connections, {len(down_connections)} DOWN"
                            devices_with_issues.append(hostname)
                        else:
                            output += f"\n🟢 {hostname} ({device_id}) - {conn_count} connections (all UP)"
                    else:
                        output += f"\n⚠️  {hostname} ({device_id}) - No connection data"
                except Exception as e:
                    output += f"\n❌ {hostname} ({device_id}) - Error fetching connections"
            
            output += f"""

📈 Summary:
- Total Control Connections: {total_connections}
- Devices with Issues: {len(devices_with_issues)}"""
            
            if devices_with_issues:
                output += "\n\n⚠️  Devices with connection issues:"
                for dev in devices_with_issues:
                    output += f"\n  • {dev}"
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting control connections: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_bfd_sessions(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get BFD (Bidirectional Forwarding Detection) sessions status
    
    Retrieves BFD session information for monitoring tunnel health between devices.
    BFD sessions provide fast failure detection for overlay tunnels in the SD-WAN fabric.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns BFD sessions for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Device hostname and system IP
        - BFD session state (up/down)
        - Source and destination information
        - Color (transport type)
        - Transitions and uptime
    """
    logger.info(f"Executing get_bfd_sessions for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get BFD sessions for specific device
        if device_id and device_id.strip():
            bfd_data = await api.get_bfd_sessions(device_id.strip())
            
            if not bfd_data:
                return f"❌ No BFD session data found for device {device_id}"
            
            output = f"""✅ BFD Sessions Status

📊 Device: {device_id}
🔗 Total BFD Sessions: {len(bfd_data)}
"""
            
            up_sessions = 0
            down_sessions = 0
            
            for session in bfd_data:
                state = session.get('state', 'N/A')
                src_ip = session.get('src-ip', 'N/A')
                dst_ip = session.get('dst-ip', 'N/A')
                src_color = session.get('src-color', 'N/A')
                dst_color = session.get('dst-color', 'N/A')
                transitions = session.get('transitions', 'N/A')
                uptime = session.get('uptime', 'N/A')
                
                if state == "up":
                    state_icon = "🟢"
                    up_sessions += 1
                else:
                    state_icon = "🔴"
                    down_sessions += 1
                
                output += f"\n{state_icon} {src_ip} ({src_color}) ↔ {dst_ip} ({dst_color})"
                output += f"\n   State: {state} | Transitions: {transitions} | Uptime: {uptime}"
            
            output += f"""

📈 Session Summary:
🟢 Up: {up_sessions} sessions
🔴 Down: {down_sessions} sessions"""
            
            return output
        
        # Otherwise, get BFD sessions for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ BFD Sessions Status - All Devices

📊 Total Devices: {len(devices)}
"""
            
            total_up = 0
            total_down = 0
            devices_with_down_sessions = []
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                
                try:
                    bfd_data = await api.get_bfd_sessions(device_id)
                    
                    if bfd_data:
                        up_count = sum(1 for s in bfd_data if s.get('state') == 'up')
                        down_count = len(bfd_data) - up_count
                        
                        total_up += up_count
                        total_down += down_count
                        
                        if down_count > 0:
                            output += f"\n⚠️  {hostname} ({device_id}) - {up_count} UP, {down_count} DOWN"
                            devices_with_down_sessions.append(hostname)
                        else:
                            output += f"\n🟢 {hostname} ({device_id}) - {up_count} sessions (all UP)"
                    else:
                        output += f"\n⚠️  {hostname} ({device_id}) - No BFD data"
                except Exception as e:
                    output += f"\n❌ {hostname} ({device_id}) - Error fetching BFD sessions"
            
            output += f"""

📈 Global Summary:
🟢 Total UP Sessions: {total_up}
🔴 Total DOWN Sessions: {total_down}
⚠️  Devices with Issues: {len(devices_with_down_sessions)}"""
            
            if devices_with_down_sessions:
                output += "\n\n⚠️  Devices with down BFD sessions:"
                for dev in devices_with_down_sessions:
                    output += f"\n  • {dev}"
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting BFD sessions: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_interfaces(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get interface information, IP addresses, and statistics
    
    Retrieves comprehensive interface data including operational status, IP addresses,
    bandwidth, MTU, and traffic statistics for all interfaces on devices.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns interface information for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Interface name and type
        - Operational status (up/down)
        - IP address and subnet mask
        - MAC address
        - Bandwidth and MTU
        - RX/TX packets and bytes
        - Error statistics
    """
    logger.info(f"Executing get_interfaces for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get interfaces for specific device
        if device_id and device_id.strip():
            interface_data = await api.get_interfaces(device_id.strip())
            
            if not interface_data:
                return f"❌ No interface data found for device {device_id}"
            
            output = f"""✅ Interface Information and Statistics

📊 Device: {device_id}
🔌 Total Interfaces: {len(interface_data)}
"""
            
            for intf in interface_data:
                ifname = intf.get('ifname', 'N/A')
                if_admin_status = intf.get('if-admin-status', 'N/A')
                if_oper_status = intf.get('if-oper-status', 'N/A')
                ip_address = intf.get('ip-address', 'N/A')
                ipv4_subnet_mask = intf.get('ipv4-subnet-mask', 'N/A')
                hwaddr = intf.get('hwaddr', 'N/A')
                speed_mbps = intf.get('speed-mbps', 'N/A')
                mtu = intf.get('mtu', 'N/A')
                rx_packets = intf.get('rx-packets', 0)
                tx_packets = intf.get('tx-packets', 0)
                rx_octets = intf.get('rx-octets', 0)
                tx_octets = intf.get('tx-octets', 0)
                rx_errors = intf.get('rx-errors', 0)
                tx_errors = intf.get('tx-errors', 0)
                
                # Convert bytes to human readable
                rx_mb = rx_octets / (1024 * 1024)
                tx_mb = tx_octets / (1024 * 1024)
                
                status_icon = "🟢" if if_oper_status == "if-oper-state-ready" else "🔴"
                
                output += f"""
{status_icon} Interface: {ifname}
   Admin Status: {if_admin_status} | Oper Status: {if_oper_status}
   IP Address: {ip_address}/{ipv4_subnet_mask}
   MAC Address: {hwaddr}
   Speed: {speed_mbps} Mbps | MTU: {mtu}
   📥 RX: {rx_packets:,} packets ({rx_mb:.2f} MB) | Errors: {rx_errors}
   📤 TX: {tx_packets:,} packets ({tx_mb:.2f} MB) | Errors: {tx_errors}
"""
            
            return output
        
        # Otherwise, get interfaces for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ Interface Summary - All Devices

📊 Total Devices: {len(devices)}
"""
            
            total_interfaces = 0
            total_up = 0
            total_down = 0
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                
                try:
                    interface_data = await api.get_interfaces(device_id)
                    
                    if interface_data:
                        intf_count = len(interface_data)
                        total_interfaces += intf_count
                        
                        up_count = sum(1 for i in interface_data if i.get('if-oper-status') == 'if-oper-state-ready')
                        down_count = intf_count - up_count
                        
                        total_up += up_count
                        total_down += down_count
                        
                        if down_count > 0:
                            output += f"\n⚠️  {hostname} ({device_id}) - {intf_count} interfaces: {up_count} UP, {down_count} DOWN"
                        else:
                            output += f"\n🟢 {hostname} ({device_id}) - {intf_count} interfaces (all UP)"
                    else:
                        output += f"\n⚠️  {hostname} ({device_id}) - No interface data"
                except Exception as e:
                    output += f"\n❌ {hostname} ({device_id}) - Error fetching interfaces"
            
            output += f"""

📈 Global Summary:
🔌 Total Interfaces: {total_interfaces}
🟢 Operational: {total_up}
🔴 Down: {total_down}"""
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_bgp_monitoring(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get real-time BGP monitoring information including neighbors, summary, and routes
    
    Retrieves comprehensive BGP routing protocol information including neighbor relationships,
    BGP session state, received/advertised prefixes, routing table statistics, and actual
    BGP routes learned from neighbors.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns BGP information for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - BGP neighbor IP addresses
        - BGP session state (Established/Active/Idle)
        - AS numbers
        - Received and advertised prefix counts
        - BGP routes (prefix, next-hop, AS path, local preference)
        - Uptime information
    """
    logger.info(f"Executing get_bgp_monitoring for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get BGP info for specific device
        if device_id and device_id.strip():
            bgp_neighbors = await api.get_bgp_neighbors(device_id.strip())
            
            try:
                bgp_summary = await api.get_bgp_summary(device_id.strip())
            except:
                bgp_summary = []
            
            try:
                bgp_routes = await api.get_bgp_routes(device_id.strip())
            except:
                bgp_routes = []
            
            if not bgp_neighbors and not bgp_summary and not bgp_routes:
                return f"❌ No BGP data found for device {device_id}"
            
            output = f"""✅ BGP Real-Time Monitoring

📊 Device: {device_id}
"""
            
            if bgp_summary:
                for summary in bgp_summary:
                    router_id = summary.get('router-id', 'N/A')
                    local_as = summary.get('local-as', 'N/A')
                    output += f"\n🔷 Router ID: {router_id} | Local AS: {local_as}"
            
            if bgp_neighbors:
                output += f"\n\n🤝 BGP Neighbors ({len(bgp_neighbors)}):\n"
                
                for neighbor in bgp_neighbors:
                    peer_addr = neighbor.get('peer-addr', 'N/A')
                    peer_as = neighbor.get('as', 'N/A')
                    state = neighbor.get('state', 'N/A')
                    prefixes_received = neighbor.get('prefixes-received', 0)
                    prefixes_installed = neighbor.get('prefixes-installed', 0)
                    uptime = neighbor.get('up-time', 'N/A')
                    
                    state_icon = "🟢" if state == "established" else "🔴"
                    
                    output += f"""{state_icon} Neighbor: {peer_addr} (AS {peer_as})
   State: {state} | Uptime: {uptime}
   Prefixes: {prefixes_received} received, {prefixes_installed} installed
"""
            else:
                output += "\n\n⚠️  No BGP neighbors configured"
            
            # Add BGP routes information
            if bgp_routes:
                output += f"\n\n📋 BGP Routes ({len(bgp_routes)} routes):\n"
                
                # Show first 20 routes to avoid excessive output
                routes_to_show = bgp_routes[:20]
                
                for route in routes_to_show:
                    prefix = route.get('prefix', 'N/A')
                    next_hop = route.get('next-hop', 'N/A')
                    as_path = route.get('as-path', 'N/A')
                    local_pref = route.get('local-pref', 'N/A')
                    origin = route.get('origin', 'N/A')
                    metric = route.get('metric', 'N/A')
                    
                    output += f"""   🌐 {prefix}
      Next Hop: {next_hop} | AS Path: {as_path}
      Local Pref: {local_pref} | Origin: {origin} | Metric: {metric}
"""
                
                if len(bgp_routes) > 20:
                    output += f"\n   ... and {len(bgp_routes) - 20} more routes"
            else:
                output += "\n\n⚠️  No BGP routes found"
            
            return output
        
        # Otherwise, get BGP info for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ BGP Monitoring - All Devices

📊 Total Devices: {len(devices)}
"""
            
            devices_with_bgp = 0
            total_neighbors = 0
            total_established = 0
            total_routes = 0
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                
                try:
                    bgp_neighbors = await api.get_bgp_neighbors(device_id)
                    
                    # Try to get routes count
                    route_count = 0
                    try:
                        bgp_routes = await api.get_bgp_routes(device_id)
                        route_count = len(bgp_routes) if bgp_routes else 0
                        total_routes += route_count
                    except:
                        pass
                    
                    if bgp_neighbors:
                        devices_with_bgp += 1
                        neighbor_count = len(bgp_neighbors)
                        total_neighbors += neighbor_count
                        
                        established_count = sum(1 for n in bgp_neighbors if n.get('state') == 'established')
                        total_established += established_count
                        
                        if established_count < neighbor_count:
                            output += f"\n⚠️  {hostname} ({device_id}) - {established_count}/{neighbor_count} BGP sessions, {route_count} routes"
                        else:
                            output += f"\n🟢 {hostname} ({device_id}) - {neighbor_count} BGP neighbors, {route_count} routes"
                    else:
                        output += f"\n⚪ {hostname} ({device_id}) - No BGP configured"
                except Exception as e:
                    output += f"\n❌ {hostname} ({device_id}) - Error fetching BGP data"
            
            output += f"""

📈 Global Summary:
- Devices with BGP: {devices_with_bgp}
- Total BGP Neighbors: {total_neighbors}
- Established Sessions: {total_established}
- Total BGP Routes: {total_routes}"""
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting BGP monitoring: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_omp_monitoring(
    device_id: Optional[str] = None,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get real-time OMP (Overlay Management Protocol) monitoring information with detailed routes and TLOCs
    
    Retrieves comprehensive OMP routing information including peer relationships, OMP session state,
    advertised and received routes and TLOCs, and TLOC (Transport Location) information.
    OMP is the control plane protocol unique to Cisco SD-WAN.
    
    Args:
        device_id: Optional. System IP address of specific device. If not provided,
                   returns OMP information for all devices
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - OMP peer IP addresses and session state
        - Peer type (vSmart/vEdge)
        - OMP summary (routes/TLOCs received, installed, sent)
        - Detailed list of routes received
        - Detailed list of routes advertised (sent)
        - Detailed list of TLOCs received
        - Detailed list of TLOCs advertised (sent)
        - Uptime information
    """
    logger.info(f"Executing get_omp_monitoring for device: {device_id}")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # If device_id provided, get OMP info for specific device
        if device_id and device_id.strip():
            omp_peers = await api.get_omp_peers(device_id.strip())
            
            try:
                omp_summary = await api.get_omp_summary(device_id.strip())
            except:
                omp_summary = []
            
            try:
                omp_routes_received = await api.get_omp_routes_received(device_id.strip())
            except:
                omp_routes_received = []
            
            try:
                omp_routes_advertised = await api.get_omp_routes_advertised(device_id.strip())
            except:
                omp_routes_advertised = []
            
            try:
                omp_tlocs_received = await api.get_omp_tlocs_received(device_id.strip())
            except:
                omp_tlocs_received = []
            
            try:
                omp_tlocs_advertised = await api.get_omp_tlocs_advertised(device_id.strip())
            except:
                omp_tlocs_advertised = []
            
            if not omp_peers and not omp_summary:
                return f"❌ No OMP data found for device {device_id}"
            
            output = f"""✅ OMP Real-Time Monitoring

📊 Device: {device_id}
"""
            
            # Display OMP Summary
            if omp_summary:
                output += "\n🔷 OMP Summary:\n"
                for summary in omp_summary:
                    oper_state = summary.get('operstate', 'N/A')
                    personality = summary.get('personality', 'N/A')
                    routes_received = summary.get('routes-received', 0)
                    routes_installed = summary.get('routes-installed', 0)
                    routes_sent = summary.get('routes-sent', 0)
                    tlocs_received = summary.get('tlocs-received', 0)
                    tlocs_installed = summary.get('tlocs-installed', 0)
                    tlocs_sent = summary.get('tlocs-sent', 0)
                    vsmart_peers = summary.get('vsmart-peers', 0)
                    
                    output += f"""   OMP State: {oper_state} | Device Type: {personality}
   Routes: {routes_received} received, {routes_installed} installed, {routes_sent} sent
   TLOCs: {tlocs_received} received, {tlocs_installed} installed, {tlocs_sent} sent
   vSmart Peers: {vsmart_peers}
"""
            
            # Display OMP Peers
            if omp_peers:
                output += f"\n🤝 OMP Peers ({len(omp_peers)}):\n"
                
                for peer in omp_peers:
                    peer_addr = peer.get('peer', 'N/A')
                    peer_type = peer.get('type', 'N/A')
                    state = peer.get('state', 'N/A')
                    routes_received = peer.get('routes-received', 0)
                    routes_installed = peer.get('routes-installed', 0)
                    routes_sent = peer.get('routes-sent', 0)
                    tlocs_received = peer.get('tlocs-received', 0)
                    tlocs_installed = peer.get('tlocs-installed', 0)
                    tlocs_sent = peer.get('tlocs-sent', 0)
                    uptime = peer.get('up-time', 'N/A')
                    
                    state_icon = "🟢" if state == "up" else "🔴"
                    
                    output += f"""{state_icon} Peer: {peer_addr} ({peer_type})
   State: {state} | Uptime: {uptime}
   Routes: {routes_received} rcvd, {routes_installed} installed, {routes_sent} sent
   TLOCs: {tlocs_received} rcvd, {tlocs_installed} installed, {tlocs_sent} sent
"""
            else:
                output += "\n\n⚠️  No OMP peers found"
            
            # Display detailed OMP Routes Received
            if omp_routes_received:
                output += f"\n\n📥 OMP Routes Received ({len(omp_routes_received)} routes):\n"
                # Show first 10 routes to avoid excessive output
                routes_to_show = omp_routes_received[:10]
                
                for route in routes_to_show:
                    vpn_id = route.get('vpn-id', 'N/A')
                    prefix = route.get('prefix', 'N/A')
                    protocol = route.get('protocol', 'N/A')
                    from_peer = route.get('from-peer', 'N/A')
                    status = route.get('status', 'N/A')
                    preference = route.get('preference', 'N/A')
                    originator = route.get('originator', 'N/A')
                    
                    output += f"""   🌐 VPN {vpn_id}: {prefix}
      Protocol: {protocol} | From: {from_peer} | Status: {status}
      Preference: {preference} | Originator: {originator}
"""
                
                if len(omp_routes_received) > 10:
                    output += f"   ... and {len(omp_routes_received) - 10} more routes\n"
            else:
                output += "\n\n⚠️  No OMP routes received"
            
            # Display detailed OMP Routes Advertised (Sent)
            if omp_routes_advertised:
                output += f"\n📤 OMP Routes Advertised/Sent ({len(omp_routes_advertised)} routes):\n"
                # Show first 10 routes to avoid excessive output
                routes_to_show = omp_routes_advertised[:10]
                
                for route in routes_to_show:
                    vpn_id = route.get('vpn-id', 'N/A')
                    prefix = route.get('prefix', 'N/A')
                    protocol = route.get('protocol', 'N/A')
                    to_peer = route.get('to-peer', 'N/A')
                    preference = route.get('preference', 'N/A')
                    originator = route.get('originator', 'N/A')
                    
                    output += f"""   🌐 VPN {vpn_id}: {prefix}
      Protocol: {protocol} | To: {to_peer}
      Preference: {preference} | Originator: {originator}
"""
                
                if len(omp_routes_advertised) > 10:
                    output += f"   ... and {len(omp_routes_advertised) - 10} more routes\n"
            else:
                output += "\n⚠️  No OMP routes advertised"
            
            # Display detailed OMP TLOCs Received
            if omp_tlocs_received:
                output += f"\n📥 OMP TLOCs Received ({len(omp_tlocs_received)} TLOCs):\n"
                # Show first 10 TLOCs to avoid excessive output
                tlocs_to_show = omp_tlocs_received[:10]
                
                for tloc in tlocs_to_show:
                    tloc_ip = tloc.get('tloc', 'N/A')
                    color = tloc.get('color', 'N/A')
                    encap = tloc.get('encap', 'N/A')
                    from_peer = tloc.get('from-peer', 'N/A')
                    status = tloc.get('status', 'N/A')
                    
                    output += f"""   📍 TLOC: {tloc_ip}
      Color: {color} | Encap: {encap} | From: {from_peer} | Status: {status}
"""
                
                if len(omp_tlocs_received) > 10:
                    output += f"   ... and {len(omp_tlocs_received) - 10} more TLOCs\n"
            else:
                output += "\n⚠️  No OMP TLOCs received"
            
            # Display detailed OMP TLOCs Advertised (Sent)
            if omp_tlocs_advertised:
                output += f"\n📤 OMP TLOCs Advertised/Sent ({len(omp_tlocs_advertised)} TLOCs):\n"
                # Show first 10 TLOCs to avoid excessive output
                tlocs_to_show = omp_tlocs_advertised[:10]
                
                for tloc in tlocs_to_show:
                    tloc_ip = tloc.get('tloc', 'N/A')
                    color = tloc.get('color', 'N/A')
                    encap = tloc.get('encap', 'N/A')
                    to_peer = tloc.get('to-peer', 'N/A')
                    
                    output += f"""   📍 TLOC: {tloc_ip}
      Color: {color} | Encap: {encap} | To: {to_peer}
"""
                
                if len(omp_tlocs_advertised) > 10:
                    output += f"   ... and {len(omp_tlocs_advertised) - 10} more TLOCs\n"
            else:
                output += "\n⚠️  No OMP TLOCs advertised"
            
            return output
        
        # Otherwise, get OMP info for all devices
        else:
            devices = await api.get_devices()
            
            if not devices:
                return "❌ No devices found"
            
            output = f"""✅ OMP Monitoring - All Devices

📊 Total Devices: {len(devices)}
"""
            
            total_peers = 0
            total_up = 0
            total_routes_received = 0
            total_routes_sent = 0
            total_tlocs_received = 0
            total_tlocs_sent = 0
            devices_with_issues = []
            
            for device in devices:
                device_id = device.get('system-ip')
                hostname = device.get('host-name', 'N/A')
                
                try:
                    omp_peers = await api.get_omp_peers(device_id)
                    
                    # Get OMP summary for counts
                    try:
                        omp_summary = await api.get_omp_summary(device_id)
                        if omp_summary:
                            for summary in omp_summary:
                                routes_recv = summary.get('routes-received', 0)
                                routes_sent = summary.get('routes-sent', 0)
                                tlocs_recv = summary.get('tlocs-received', 0)
                                tlocs_sent = summary.get('tlocs-sent', 0)
                                total_routes_received += routes_recv
                                total_routes_sent += routes_sent
                                total_tlocs_received += tlocs_recv
                                total_tlocs_sent += tlocs_sent
                    except:
                        pass
                    
                    if omp_peers:
                        peer_count = len(omp_peers)
                        total_peers += peer_count
                        
                        up_count = sum(1 for p in omp_peers if p.get('state') == 'up')
                        total_up += up_count
                        
                        if up_count < peer_count:
                            output += f"\n⚠️  {hostname} ({device_id}) - {up_count}/{peer_count} OMP peers UP"
                            devices_with_issues.append(hostname)
                        else:
                            output += f"\n🟢 {hostname} ({device_id}) - {peer_count} OMP peers (all UP)"
                    else:
                        output += f"\n⚪ {hostname} ({device_id}) - No OMP peers"
                except Exception as e:
                    output += f"\n❌ {hostname} ({device_id}) - Error fetching OMP data"
            
            output += f"""

📈 Global Summary:
- Total OMP Peers: {total_peers}
- Peers UP: {total_up}
- Total Routes Received: {total_routes_received}
- Total Routes Sent: {total_routes_sent}
- Total TLOCs Received: {total_tlocs_received}
- Total TLOCs Sent: {total_tlocs_sent}
- Devices with Issues: {len(devices_with_issues)}"""
            
            if devices_with_issues:
                output += "\n\n⚠️  Devices with OMP issues:"
                for dev in devices_with_issues:
                    output += f"\n  • {dev}"
            
            return output
        
    except Exception as e:
        logger.error(f"Error getting OMP monitoring: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_configuration_groups(
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get configuration groups and their associated devices
    
    Retrieves all configuration groups defined in the SD-WAN fabric along with
    the devices associated with each group. Configuration groups provide a way
    to manage device configurations at scale using templates and profiles.
    
    Args:
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Configuration group name
        - Group description
        - Solution type (SD-WAN, SD-Routing, etc.)
        - Associated devices count
        - List of devices in each group
        - Device deployment status
    """
    logger.info("Executing get_configuration_groups")
    
    try:
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        config_groups = await api.get_configuration_groups()
        
        if not config_groups:
            return "⚠️  No configuration groups found"
        
        output = f"""✅ Configuration Groups and Device Associations

📊 Total Configuration Groups: {len(config_groups)}
"""
        
        total_devices = 0
        
        for group in config_groups:
            # Handle both dict and other formats
            if not isinstance(group, dict):
                logger.warning(f"Unexpected group format: {type(group)}")
                continue
                
            group_name = group.get('name', group.get('groupName', 'N/A'))
            group_id = group.get('id', group.get('groupId', 'N/A'))
            description = group.get('description', 'No description')
            solution = group.get('solution', group.get('solutionType', 'N/A'))
            
            # Get associated devices - try multiple possible keys
            devices = group.get('devices', group.get('associatedDevices', []))
            
            # Handle case where devices might be in a different structure
            if not devices:
                # Try to get device count from metadata
                device_count = group.get('deviceCount', group.get('devicesCount', 0))
            else:
                device_count = len(devices) if devices else 0
            
            total_devices += device_count
            
            output += f"""
{'='*60}
📦 Configuration Group: {group_name}
   ID: {group_id}
   Description: {description}
   Solution: {solution}
   Associated Devices: {device_count}
"""
            
            if devices and device_count > 0:
                output += "\n   Devices:\n"
                for device in devices:
                    if isinstance(device, dict):
                        device_id = device.get('id', device.get('deviceId', device.get('systemIp', 'N/A')))
                        device_name = device.get('name', device.get('hostname', device.get('hostName', 'N/A')))
                        deploy_status = device.get('deploymentStatus', device.get('status', device.get('configStatus', 'N/A')))
                        output += f"     🖥️  {device_name} ({device_id}) - Status: {deploy_status}\n"
                    elif isinstance(device, str):
                        # Sometimes devices are just IDs
                        output += f"     🖥️  {device}\n"
                    else:
                        output += f"     🖥️  {str(device)}\n"
            else:
                output += "\n   ⚠️  No devices associated with this group\n"
        
        output += f"""
{'='*60}
📈 Summary:
- Total Configuration Groups: {len(config_groups)}
- Total Devices Managed: {total_devices}
"""
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting configuration groups: {e}", exc_info=True)
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_application_health(
    site_id: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get application health statistics for all applications at a specific site
    
    Retrieves comprehensive application performance and health metrics for a specific site
    in the SD-WAN fabric. This includes application latency, loss, jitter, and QoE (Quality
    of Experience) scores for all applications running at the site.
    
    QoE Categories:
    - Good: QoE 8-10
    - Fair: QoE 5 to <8
    - Poor: QoE 0 to <5
    
    Args:
        site_id: Required. Site ID to query application health for (e.g., '100', '200')
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Site ID
        - Total number of applications monitored
        - Application names
        - QoE scores and status (Good/Fair/Poor)
        - Performance metrics (latency, loss, jitter)
        - Application family/category
        - Summary of applications by QoE category
    """
    logger.info(f"Executing get_application_health for site: {site_id}")
    
    try:
        if not site_id or not site_id.strip():
            return "❌ Error: site_id parameter is required"
        
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        app_health_data = await api.get_application_health_by_site(site_id.strip())
        
        if not app_health_data:
            return f"❌ No application health data found for site {site_id}"
        
        output = f"""✅ Application Health Report - Site {site_id}

📊 Total Applications Monitored: {len(app_health_data)}
"""
        
        # Count applications by QoE status
        good_apps = 0
        fair_apps = 0
        poor_apps = 0
        unknown_apps = 0
        
        for app in app_health_data:
            app_name = app.get('application', app.get('app-name', app.get('name', 'N/A')))
            app_family = app.get('family', app.get('app-family', 'N/A'))
            qoe = app.get('qoe', 'N/A')
            latency = app.get('latency', app.get('avg-latency', 'N/A'))
            loss = app.get('loss', app.get('avg-loss', 'N/A'))
            jitter = app.get('jitter', app.get('avg-jitter', 'N/A'))
            
            # Determine QoE status based on QoE score
            # Good: QoE 8-10
            # Fair: QoE 5 to <8
            # Poor: QoE 0 to <5
            try:
                if isinstance(qoe, (int, float)):
                    qoe_value = float(qoe)
                    if qoe_value >= 8:
                        status_icon = "🟢"
                        status_text = "Good"
                        good_apps += 1
                    elif qoe_value >= 5:
                        status_icon = "🟡"
                        status_text = "Fair"
                        fair_apps += 1
                    else:
                        status_icon = "🔴"
                        status_text = "Poor"
                        poor_apps += 1
                else:
                    status_icon = "⚪"
                    status_text = "Unknown"
                    unknown_apps += 1
            except:
                status_icon = "⚪"
                status_text = "Unknown"
                unknown_apps += 1
            
            output += f"""
{status_icon} Application: {app_name}
   Family: {app_family}
   QoE Score: {qoe} ({status_text})
   Latency: {latency} ms | Loss: {loss}% | Jitter: {jitter} ms
"""
        
        output += f"""
{'='*60}
📈 QoE Summary:
🟢 Good (QoE 8-10): {good_apps} application(s)
🟡 Fair (QoE 5-<8): {fair_apps} application(s)
🔴 Poor (QoE 0-<5): {poor_apps} application(s)"""
        
        if unknown_apps > 0:
            output += f"\n⚪ Unknown: {unknown_apps} application(s)"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting application health: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def start_nwpi_trace(
    site_id: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Start a Network Wide Path Insight (NWPI) trace for a specific site
    
    This tool initiates an NWPI trace that runs for 1 minute to capture network flow events.
    After calling this tool, wait approximately 70 seconds before calling analyze_nwpi_trace
    with the returned trace_id and entry_time values.
    
    The trace captures:
    - Application visibility data
    - QoS monitoring data
    - ART (Application Response Time) visibility
    - Drop and block events
    
    Args:
        site_id: Required. Site ID to run the NWPI trace for (e.g., '14', '100')
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Trace ID (needed for analyze_nwpi_trace)
        - Entry Time (needed for analyze_nwpi_trace)
        - Trace status and device information
        - Instructions for next steps
    """
    logger.info(f"Executing start_nwpi_trace for site: {site_id}")
    
    try:
        if not site_id or not site_id.strip():
            return "❌ Error: site_id parameter is required"
        
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        # Start the NWPI trace
        try:
            trace_response = await api.start_nwpi_trace(site_id.strip())
        except Exception as e:
            return f"❌ Error starting NWPI trace: {str(e)}"
        
        trace_id = trace_response.get('trace-id')
        entry_time = trace_response.get('entry_time')
        trace_name = trace_response.get('trace-name', f'trace_{trace_id}')
        state = trace_response.get('state', 'unknown')
        expire_time = trace_response.get('expire-time', 'N/A')
        
        if not trace_id or not entry_time:
            return f"❌ Error: Invalid response from trace start - missing trace-id or entry_time"
        
        output = f"""✅ NWPI Trace Started Successfully!

{'='*60}
📊 TRACE DETAILS (SAVE THESE VALUES)
{'='*60}

🔑 Trace ID: {trace_id}
⏰ Entry Time: {entry_time}
📝 Trace Name: {trace_name}
📍 Site ID: {site_id}
🔄 State: {state}
⏳ Expires: {expire_time}
"""
        
        # Log the devices involved in the trace
        traces = trace_response.get('traces', [])
        if traces:
            output += f"\n📍 Devices Participating in Trace:\n"
            for trace in traces:
                device_ip = trace.get('device-ip', 'N/A')
                local_system_ip = trace.get('local-system-ip', 'N/A')
                status = trace.get('status', 'N/A')
                message = trace.get('message', 'N/A')
                output += f"   • Device IP: {device_ip} (System IP: {local_system_ip})\n"
                output += f"     Status: {status} - {message}\n"
        
        output += f"""
{'='*60}
⏳ NEXT STEPS
{'='*60}

1. Wait approximately 70 seconds for the trace to complete
2. Then call analyze_nwpi_trace with the following parameters:
   
   trace_id: {trace_id}
   entry_time: {entry_time}

Example:
   analyze_nwpi_trace(trace_id="{trace_id}", entry_time="{entry_time}")
"""
        
        return output
        
    except Exception as e:
        logger.error(f"Error starting NWPI trace: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def analyze_nwpi_trace(
    trace_id: str,
    entry_time: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Export and analyze a completed NWPI trace
    
    This tool exports a previously started NWPI trace and analyzes the hop-level flow events
    for drops, blocks, and other network issues. Call this tool approximately 70 seconds
    after starting a trace with start_nwpi_trace.
    
    The analysis looks for:
    - URLF (URL Filtering) blocks
    - Firewall blocks (L4/L7)
    - Zone-Based Firewall (ZBFW) drops/blocks
    - UTD (Unified Threat Defense) inspection blocks
    - Routing issues (No adjacency, No route)
    - QoS drops
    - NAT drops
    - Interface drops
    - Policer drops
    - ACL drops
    - And other network events
    
    Args:
        trace_id: Required. The trace ID returned by start_nwpi_trace
        entry_time: Required. The entry_time returned by start_nwpi_trace
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables
    
    Returns:
        Formatted string containing:
        - Detailed analysis of detected events
        - Impacted applications and drop/block reasons
        - Policy information (ZBFW policies, UTD profiles)
        - Security Group Tags (SGT)
        - Summary of findings
    """
    logger.info(f"Executing analyze_nwpi_trace for trace_id: {trace_id}")
    
    try:
        if not trace_id or not str(trace_id).strip():
            return "❌ Error: trace_id parameter is required"
        if not entry_time or not str(entry_time).strip():
            return "❌ Error: entry_time parameter is required"
        
        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api
        
        await api.authenticate()
        
        output = f"""🔍 NWPI Trace Analysis

{'='*60}
📊 Trace ID: {trace_id}
⏰ Entry Time: {entry_time}
{'='*60}

📥 Exporting Trace Data...
"""
        
        # Export the trace with retries
        max_retries = 6  # Retry up to 6 times (60 seconds additional)
        retry_delay = 10
        trace_data = None
        
        for attempt in range(max_retries):
            try:
                trace_data = await api.export_nwpi_trace(str(trace_id).strip(), str(entry_time).strip())
                output += f"✅ Trace exported successfully!\n"
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Export attempt {attempt + 1} failed, retrying in {retry_delay}s: {e}")
                    output += f"⏳ Export attempt {attempt + 1} failed, retrying in {retry_delay}s...\n"
                    await asyncio.sleep(retry_delay)
                else:
                    return output + f"\n❌ Error: Failed to export trace after {max_retries} attempts: {str(e)}\n\n💡 The trace may still be running. Please wait a few more seconds and try again."
        
        if not trace_data:
            return output + "\n❌ Error: No trace data received"
        
        # Extract and analyze the tar.gz file
        output += f"\n{'='*60}\n🔬 Analyzing Trace Data (nwpihopsofflow_0.json)...\n"
        
        try:
            # Extract tar.gz in memory
            tar_buffer = io.BytesIO(trace_data)
            flow_events = []
            
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                # Look for nwpihopsofflow_0.json at root level
                for member in tar.getmembers():
                    if member.name.endswith('nwpihopsofflow_0.json') or member.name == 'nwpihopsofflow_0.json':
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8')
                            # The file contains multiple JSON objects (one per line)
                            for line in content.strip().split('\n'):
                                if line.strip():
                                    try:
                                        event = json.loads(line)
                                        flow_events.append(event)
                                    except json.JSONDecodeError:
                                        continue
                        break
            
            if not flow_events:
                output += "⚠️  No flow events found in trace data\n"
                return output + f"\n{'='*60}\n📊 Trace completed but no events were captured during the trace window.\n\n💡 This could mean:\n   • No traffic was flowing during the capture\n   • The site has no active applications\n   • Try running another trace during peak traffic hours"
            
            output += f"📊 Total Hop Flow Events: {len(flow_events)}\n"
            
            # Define categories for problematic events
            problematic_events = {
                'URLF_BLOCKING': {'name': 'URL Filtering Block', 'events': [], 'icon': '🚫'},
                'FirewallL4': {'name': 'Firewall L4 Drop', 'events': [], 'icon': '🔥'},
                'FirewallL7': {'name': 'Firewall L7 Drop', 'events': [], 'icon': '🔥'},
                'UTDSrvNodeRequest': {'name': 'UTD Service Node Drop', 'events': [], 'icon': '🔒'},
                'UTDDrop': {'name': 'UTD Drop', 'events': [], 'icon': '🔒'},
                'Ipv4NoAdj': {'name': 'IPv4 No Adjacency', 'events': [], 'icon': '🔌'},
                'Ipv4NoRoute': {'name': 'IPv4 No Route', 'events': [], 'icon': '🛣️'},
                'Ipv6NoAdj': {'name': 'IPv6 No Adjacency', 'events': [], 'icon': '🔌'},
                'Ipv6NoRoute': {'name': 'IPv6 No Route', 'events': [], 'icon': '🛣️'},
                'QosDrops': {'name': 'QoS Drops', 'events': [], 'icon': '📉'},
                'NatDrop': {'name': 'NAT Drop', 'events': [], 'icon': '🔄'},
                'NatNoSession': {'name': 'NAT No Session', 'events': [], 'icon': '🔄'},
                'InterfaceDrop': {'name': 'Interface Drop', 'events': [], 'icon': '🔌'},
                'PolicerDrop': {'name': 'Policer Drop', 'events': [], 'icon': '🚔'},
                'AclDrop': {'name': 'ACL Drop', 'events': [], 'icon': '🚷'},
                'TcpOptDrop': {'name': 'TCP Option Drop', 'events': [], 'icon': '📡'},
                'IpsecDrop': {'name': 'IPSec Drop', 'events': [], 'icon': '🔐'},
                'FragDrop': {'name': 'Fragment Drop', 'events': [], 'icon': '💥'},
                'RpfDrop': {'name': 'RPF Drop', 'events': [], 'icon': '↩️'},
                'BIG_DROP': {'name': 'Significant Drop Rate', 'events': [], 'icon': '⚠️'},
            }
            
            # Analyze each flow event
            for event in flow_events:
                # The 'data' field contains a JSON string that needs to be parsed
                data_str = event.get('data', '{}')
                try:
                    if isinstance(data_str, str):
                        flow_data = json.loads(data_str)
                    else:
                        flow_data = data_str
                except json.JSONDecodeError:
                    flow_data = {}
                
                # Extract basic flow information from parsed data or top-level fields
                app_name = flow_data.get('app_name', event.get('data_app_name', 'Unknown'))
                src_ip = flow_data.get('src_ip', event.get('data_src_ip', 'N/A'))
                dst_ip = flow_data.get('dst_ip', event.get('data_dst_ip', 'N/A'))
                src_port = flow_data.get('src_port', event.get('data_src_port', 'N/A'))
                dst_port = flow_data.get('dst_port', event.get('data_dst_port', 'N/A'))
                protocol = flow_data.get('protocol', event.get('data_protocol', 'N/A'))
                vpn_id = flow_data.get('vpn_id', event.get('data_vpn_id', 'N/A'))
                
                # Extract SGT information
                src_sgt = flow_data.get('src_sgt', 'N/A')
                dst_sgt = flow_data.get('dst_sgt', 'N/A')
                
                # Extract flags
                urlf_blocking = flow_data.get('urlf_blocking', event.get('data_urlf_blocking', False))
                big_drop = flow_data.get('big_drop', event.get('data_big_drop', False))
                utd_diverted = flow_data.get('utd_diverted', event.get('data_utd_diverted', False))
                max_local_drop_rate = flow_data.get('max_local_drop_rate', event.get('data_max_local_drop_rate', 0))
                max_wan_drop_rate = flow_data.get('max_wan_drop_rate', event.get('data_max_wan_drop_rate', 0))
                
                # Extract policy keys and parse them
                policy_keys = flow_data.get('policy_keys', event.get('data_policy_keys', []))
                
                # Parse policy information from policy_keys
                zbfw_policy = 'N/A'
                zbfw_rule = 'N/A'
                utd_profile = 'N/A'
                data_policy = 'N/A'
                
                for pk in policy_keys:
                    if isinstance(pk, str):
                        parts = pk.split('+')
                        if parts[0] == 'zbfw' and len(parts) >= 2:
                            zbfw_policy = parts[1]
                            if len(parts) >= 3:
                                zbfw_rule = parts[2]
                        elif parts[0] == 'utd_inspection' and len(parts) >= 2:
                            utd_profile = parts[1]
                        elif parts[0] == 'data_policy' and len(parts) >= 2:
                            data_policy = parts[1]
                
                # Extract drop causes from hop lists
                drop_causes = []
                
                # Check upstream_hop_list
                upstream_hops = flow_data.get('upstream_hop_list', [])
                for hop in upstream_hops:
                    local_drops = hop.get('local_drop_causes', [])
                    for drop in local_drops:
                        if isinstance(drop, dict):
                            drop_causes.append({
                                'display_name': drop.get('display_name', 'Unknown'),
                                'cause': drop.get('cause', 0),
                                'count': drop.get('per_cause_drop_stats', 0),
                                'location': 'upstream_local',
                                'hop_index': hop.get('hop_index', 0),
                                'device': hop.get('local_system_ip', 'N/A')
                            })
                    remote_drops = hop.get('remote_drop_causes', [])
                    for drop in remote_drops:
                        if isinstance(drop, dict):
                            drop_causes.append({
                                'display_name': drop.get('display_name', 'Unknown'),
                                'cause': drop.get('cause', 0),
                                'count': drop.get('per_cause_drop_stats', 0),
                                'location': 'upstream_remote',
                                'hop_index': hop.get('hop_index', 0),
                                'device': hop.get('remote_system_ip', 'N/A')
                            })
                
                # Check downstream_hop_list
                downstream_hops = flow_data.get('downstream_hop_list', [])
                for hop in downstream_hops:
                    local_drops = hop.get('local_drop_causes', [])
                    for drop in local_drops:
                        if isinstance(drop, dict):
                            drop_causes.append({
                                'display_name': drop.get('display_name', 'Unknown'),
                                'cause': drop.get('cause', 0),
                                'count': drop.get('per_cause_drop_stats', 0),
                                'location': 'downstream_local',
                                'hop_index': hop.get('hop_index', 0),
                                'device': hop.get('local_system_ip', 'N/A')
                            })
                    remote_drops = hop.get('remote_drop_causes', [])
                    for drop in remote_drops:
                        if isinstance(drop, dict):
                            drop_causes.append({
                                'display_name': drop.get('display_name', 'Unknown'),
                                'cause': drop.get('cause', 0),
                                'count': drop.get('per_cause_drop_stats', 0),
                                'location': 'downstream_remote',
                                'hop_index': hop.get('hop_index', 0),
                                'device': hop.get('remote_system_ip', 'N/A')
                            })
                
                # Get start device
                start_device = flow_data.get('start_device', 'N/A')
                
                # Build comprehensive event info
                event_info = {
                    'app_name': app_name,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'vpn_id': vpn_id,
                    'src_sgt': src_sgt,
                    'dst_sgt': dst_sgt,
                    'zbfw_policy': zbfw_policy,
                    'zbfw_rule': zbfw_rule,
                    'utd_profile': utd_profile,
                    'data_policy': data_policy,
                    'urlf_blocking': urlf_blocking,
                    'big_drop': big_drop,
                    'utd_diverted': utd_diverted,
                    'max_local_drop_rate': max_local_drop_rate,
                    'max_wan_drop_rate': max_wan_drop_rate,
                    'drop_causes': drop_causes,
                    'start_device': start_device,
                    'policy_keys': policy_keys,
                }
                
                # Categorize the event based on flags and drop causes
                
                # Check for URLF blocking
                if urlf_blocking:
                    problematic_events['URLF_BLOCKING']['events'].append(event_info)
                
                # Check for significant drops
                if big_drop and max_local_drop_rate > 0:
                    problematic_events['BIG_DROP']['events'].append(event_info)
                
                # Check drop causes and categorize them
                for drop in drop_causes:
                    display_name = drop.get('display_name', '')
                    # Map to our categories
                    if display_name in problematic_events:
                        # Avoid duplicates by checking if already added
                        if event_info not in problematic_events[display_name]['events']:
                            problematic_events[display_name]['events'].append(event_info)
                    else:
                        # Check partial matches
                        for cause_key in problematic_events.keys():
                            if cause_key.lower() in display_name.lower() or display_name.lower() in cause_key.lower():
                                if event_info not in problematic_events[cause_key]['events']:
                                    problematic_events[cause_key]['events'].append(event_info)
                                break
            
            # Generate detailed report
            output += f"\n{'='*60}\n📋 DETAILED FINDINGS\n{'='*60}\n"
            
            issues_found = False
            total_issues = 0
            
            for event_key, event_data in problematic_events.items():
                if event_data['events']:
                    issues_found = True
                    event_count = len(event_data['events'])
                    total_issues += event_count
                    
                    output += f"\n{event_data['icon']} {event_data['name']} ({event_count} occurrence(s)):\n"
                    output += f"   {'-'*50}\n"
                    
                    # Group by application
                    app_groups = {}
                    for evt in event_data['events']:
                        app = evt['app_name']
                        if app not in app_groups:
                            app_groups[app] = []
                        app_groups[app].append(evt)
                    
                    for app, events in app_groups.items():
                        output += f"\n   📱 Application: {app} ({len(events)} event(s))\n"
                        
                        # Show up to 5 examples per application with detailed info
                        for i, evt in enumerate(events[:5]):
                            output += f"\n      ┌─ Flow {i+1} ─────────────────────────────────\n"
                            output += f"      │ Source: {evt['src_ip']}:{evt['src_port']} (SGT: {evt['src_sgt']})\n"
                            output += f"      │ Destination: {evt['dst_ip']}:{evt['dst_port']} (SGT: {evt['dst_sgt']})\n"
                            output += f"      │ Protocol: {evt['protocol']} | VPN: {evt['vpn_id']}\n"
                            output += f"      │ Device: {evt['start_device']}\n"
                            
                            # Show drop rates if significant
                            if evt['max_local_drop_rate'] > 0:
                                output += f"      │\n"
                                output += f"      │ 📉 Drop Rate: {evt['max_local_drop_rate']}% (local) / {evt['max_wan_drop_rate']}% (WAN)\n"
                            
                            # Show ZBFW details if available
                            if evt['zbfw_policy'] != 'N/A':
                                output += f"      │\n"
                                output += f"      │ 🛡️ ZBFW Policy: {evt['zbfw_policy']}\n"
                                if evt['zbfw_rule'] != 'N/A':
                                    output += f"      │    Rule: {evt['zbfw_rule']}\n"
                            
                            # Show UTD details if available
                            if evt['utd_profile'] != 'N/A':
                                output += f"      │\n"
                                output += f"      │ 🔒 UTD Profile: {evt['utd_profile']}\n"
                                if evt['utd_diverted']:
                                    output += f"      │    UTD Diverted: Yes\n"
                            
                            # Show Data Policy if available
                            if evt['data_policy'] != 'N/A':
                                output += f"      │\n"
                                output += f"      │ 📋 Data Policy: {evt['data_policy']}\n"
                            
                            # Show drop causes
                            if evt['drop_causes']:
                                output += f"      │\n"
                                output += f"      │ ❌ Drop Causes:\n"
                                seen_causes = set()
                                for drop in evt['drop_causes']:
                                    cause_key = f"{drop['display_name']}_{drop['location']}"
                                    if cause_key not in seen_causes:
                                        seen_causes.add(cause_key)
                                        output += f"      │    • {drop['display_name']} ({drop['count']} pkts) - {drop['location']}\n"
                            
                            # Show all policy keys
                            if evt['policy_keys']:
                                output += f"      │\n"
                                output += f"      │ 🔑 Policies Applied:\n"
                                for pk in evt['policy_keys'][:5]:  # Limit to first 5
                                    output += f"      │    • {pk}\n"
                                if len(evt['policy_keys']) > 5:
                                    output += f"      │    ... and {len(evt['policy_keys']) - 5} more\n"
                            
                            output += f"      └────────────────────────────────────────\n"
                        
                        if len(events) > 5:
                            output += f"\n      ... and {len(events) - 5} more events for this application\n"
            
            if not issues_found:
                output += "\n✅ No drops, blocks, or routing issues detected!\n"
                output += "   All traffic appears to be flowing normally.\n"
            
            # Summary section
            output += f"\n{'='*60}\n📈 SUMMARY\n{'='*60}\n"
            output += f"   Trace ID: {trace_id}\n"
            output += f"   Total Hop Flow Events Analyzed: {len(flow_events)}\n"
            output += f"   Total Issues Detected: {total_issues}\n\n"
            
            if issues_found:
                output += "   ⚠️  Issues by Category:\n"
                for event_key, event_data in problematic_events.items():
                    if event_data['events']:
                        output += f"      {event_data['icon']} {event_data['name']}: {len(event_data['events'])}\n"
                
                # List unique affected applications
                affected_apps = set()
                for event_data in problematic_events.values():
                    for evt in event_data['events']:
                        affected_apps.add(evt['app_name'])
                
                if affected_apps:
                    output += f"\n   📱 Affected Applications ({len(affected_apps)}):\n"
                    for app in sorted(affected_apps):
                        output += f"      • {app}\n"
                
                # List unique policies involved
                zbfw_policies = set()
                utd_profiles = set()
                for event_data in problematic_events.values():
                    for evt in event_data['events']:
                        if evt['zbfw_policy'] != 'N/A':
                            zbfw_policies.add(f"{evt['zbfw_policy']} (Rule: {evt['zbfw_rule']})")
                        if evt['utd_profile'] != 'N/A':
                            utd_profiles.add(evt['utd_profile'])
                
                if zbfw_policies:
                    output += f"\n   🛡️ ZBFW Policies Involved ({len(zbfw_policies)}):\n"
                    for policy in sorted(zbfw_policies):
                        output += f"      • {policy}\n"
                
                if utd_profiles:
                    output += f"\n   🔒 UTD Profiles Involved ({len(utd_profiles)}):\n"
                    for profile in sorted(utd_profiles):
                        output += f"      • {profile}\n"
            else:
                output += "   ✅ Network health: Good\n"
                output += "   ✅ No blocking or drop events detected\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Error analyzing trace data: {e}", exc_info=True)
            return output + f"\n❌ Error analyzing trace data: {str(e)}"
        
    except Exception as e:
        logger.error(f"Error analyzing NWPI trace: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_qos_configuration(
    device_id: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Get QoS (policer) configuration for a specific device

    This tool retrieves the Quality of Service (QoS) policer configuration that is applied
    to a specific device through its associated policy group. The policer controls bandwidth
    rate limiting and burst settings for application traffic.

    The tool performs the following steps:
    1. Finds all policy groups in the SD-WAN fabric
    2. Searches for the policy group that contains the specified device
    3. Extracts the application-priority profile from the policy group
    4. Retrieves the QoS policy (policer) configuration details

    Args:
        device_id: Required. The device system-ip or device ID to query
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables

    Returns:
        Formatted string containing:
        - Policy group name and ID
        - Application-priority profile information
        - Policer configuration (rate, burst, exceed action)
        - Profile and policy IDs (needed for updates)
    """
    logger.info(f"Executing get_qos_configuration for device: {device_id}")

    try:
        if not device_id or not str(device_id).strip():
            return "❌ Error: device_id parameter is required"

        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api

        await api.authenticate()

        output = f"""🔍 QoS Configuration Query

{'='*60}
🖥️  Device ID: {device_id}
{'='*60}

📋 Step 1: Searching for policy groups...
"""

        # Step 1: Get all policy groups
        policy_groups = await api.get_policy_groups()
        logger.info(f"Policy groups retrieved: {len(policy_groups)}")
        if policy_groups and len(policy_groups) > 0:
            logger.info(f"First PG structure: {policy_groups[0]}")
        output += f"✅ Found {len(policy_groups)} policy group(s)\n"

        # Step 2: Find which policy group contains this device
        output += f"\n📋 Step 2: Finding policy group for device {device_id}...\n"
        target_policy_group = None
        target_policy_group_name = None

        logger.info(f"Starting iteration over {len(policy_groups)} policy groups")
        for idx, pg in enumerate(policy_groups):
            logger.info(f"Processing policy group {idx + 1}/{len(policy_groups)}")
            # API returns 'id' not 'policyGroupId'
            pg_id = pg.get('id') or pg.get('policyGroupId')
            pg_name = pg.get('name', 'Unknown')
            logger.info(f"PG {idx + 1}: name='{pg_name}', id='{pg_id}'")

            if not pg_id:
                logger.warning(f"Skipping policy group with no ID: {pg_name}")
                continue

            try:
                # Get device associations for this policy group using /device/associate API
                logger.info(f"Calling API for policy group: {pg_name} (ID: {pg_id})")
                associations = await api.get_policy_group_device_associations(pg_id)
                logger.info(f"Policy group '{pg_name}': Received {len(associations)} device(s)")

                # Check if device is in this policy group
                for assoc in associations:
                    device_ip = assoc.get('deviceIP')
                    logger.info(f"Checking device: deviceIP='{device_ip}', looking for '{device_id}'")

                    # Check if deviceIP matches the provided device_id
                    if device_ip == device_id:
                        target_policy_group = pg_id
                        target_policy_group_name = pg_name
                        logger.info(f"✅ MATCH FOUND! Device {device_id} in policy group {pg_name}")
                        output += f"✅ Device found in policy group: {pg_name} (ID: {pg_id})\n"
                        break

                if target_policy_group:
                    break
            except Exception as e:
                logger.error(f"❌ Exception in policy group {pg_name}: {str(e)}", exc_info=True)
                continue

        if not target_policy_group:
            return output + f"\n❌ Error: Device {device_id} not found in any policy group\n💡 Please verify the device ID is correct"

        # Step 3: Get policy group details and find application-priority profile
        output += f"\n📋 Step 3: Retrieving policy group details...\n"
        pg_details = await api.get_policy_group_details(target_policy_group)

        profiles = pg_details.get('profiles', [])
        app_priority_profile = None

        for profile in profiles:
            if profile.get('type') == 'application-priority':
                app_priority_profile = profile
                output += f"✅ Found application-priority profile: {profile.get('name', 'Unknown')}\n"
                break

        if not app_priority_profile:
            return output + f"\n❌ No QoS configuration found\n💡 This policy group does not have an application-priority profile configured"

        profile_id = app_priority_profile.get('id')
        profile_name = app_priority_profile.get('name', 'Unknown')

        # Step 4: Get application-priority profile details
        output += f"\n📋 Step 4: Retrieving application-priority profile details...\n"
        app_priority_details = await api.get_application_priority_profile(profile_id)

        # Find policer in associatedProfileParcels -> traffic-policy -> subparcels
        associated_parcels = app_priority_details.get('associatedProfileParcels', [])

        policer_parcel = None

        # Look through associatedProfileParcels to find traffic-policy, then search its subparcels
        for parcel in associated_parcels:
            if parcel.get('parcelType') == 'traffic-policy':
                subparcels = parcel.get('subparcels', [])

                for subparcel in subparcels:
                    if subparcel.get('parcelType') == 'policer':
                        policer_parcel = subparcel
                        policer_name = subparcel.get('payload', {}).get('name', 'Unknown')
                        output += f"✅ Found policer configuration: {policer_name}\n"
                        break

                if policer_parcel:
                    break

        if not policer_parcel:
            return output + f"\n❌ No QoS policer found\n💡 The application-priority profile exists but does not have a policer configured"

        qos_policy_id = policer_parcel.get('parcelId')
        qos_policy_name = policer_parcel.get('payload', {}).get('name', 'Unknown')

        # Step 5: Get QoS policy (policer) details
        output += f"\n📋 Step 5: Retrieving QoS policer configuration...\n"
        qos_details = await api.get_qos_policy_details(profile_id, qos_policy_id)

        # Extract policer values
        payload = qos_details.get('payload', {})
        data = payload.get('data', {})
        entries = data.get('entries', [])

        if not entries:
            return output + f"\n❌ No policer entries found in configuration"

        policer_entry = entries[0]  # Get first entry
        rate_bps = policer_entry.get('rate', {}).get('value', 'N/A')
        burst_bytes = policer_entry.get('burst', {}).get('value', 'N/A')
        exceed = policer_entry.get('exceed', {}).get('value', 'N/A')

        # Convert to human-readable format
        # Rate: bits per second (bps) -> Kbps (rate / 1000)
        # Burst: bytes (keep as is)
        if rate_bps != 'N/A':
            rate_kbps = rate_bps / 1000
            rate_display = f"{rate_kbps:.2f} Kbps ({rate_bps} bps)"
        else:
            rate_display = 'N/A'

        if burst_bytes != 'N/A':
            burst_display = f"{burst_bytes} bytes"
        else:
            burst_display = 'N/A'

        output += f"""
{'='*60}
�� QoS Configuration Summary
{'='*60}

🏷️  Policy Group: {target_policy_group_name}
    └─ ID: {target_policy_group}

📋 Application-Priority Profile: {profile_name}
    └─ Profile ID: {profile_id}

🔧 Policer Configuration: {qos_policy_name}
    └─ Policy ID: {qos_policy_id}

⚙️  Policer Settings:
    • Rate:   {rate_display}
    • Burst:  {burst_display}
    • Exceed: {exceed}

{'='*60}

💡 Use the 'update_qos_policer' tool to modify rate and burst values
   Required parameters:
   - device_id: {device_id}
   - burst_bytes: <new burst value in bytes>
   - rate_kbps: <new rate value in Kbps>
"""

        return output

    except Exception as e:
        logger.error(f"Error getting QoS configuration: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def update_qos_policer(
    device_id: str,
    burst_bytes: int,
    rate_kbps: int,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Update QoS policer configuration (rate and burst) for a specific device

    IMPORTANT: This tool modifies the QoS configuration and will affect traffic shaping
    for the specified device. Use with caution and ensure you have verified the current
    configuration using 'get_qos_configuration' before making changes.

    This tool:
    1. Finds the policy group associated with the device
    2. Retrieves the current QoS policer configuration
    3. Updates ONLY the rate and burst values (preserving exceed action and name)
    4. Applies the changes to vManage
    5. Deploys the policy group to the device

    Args:
        device_id: Required. The device system-ip or device ID to update
        burst_bytes: Required. New burst value in bytes (no conversion needed)
        rate_kbps: Required. New rate value in Kbps (will be converted to bits per second for API)
        vmanage_url: Optional. Custom vManage URL (e.g., 'vmanage.example.com')
                     If not provided, uses default from environment variables

    Returns:
        Formatted string with:
        - Confirmation of changes made
        - Before/after comparison
        - Success or error status

    Note: Rate is converted from Kbps to bps. Burst is kept in bytes.
    """
    logger.info(f"Executing update_qos_policer for device: {device_id}")

    try:
        if not device_id or not str(device_id).strip():
            return "❌ Error: device_id parameter is required"
        if burst_bytes is None or burst_bytes <= 0:
            return "❌ Error: burst_bytes must be a positive integer"
        if rate_kbps is None or rate_kbps <= 0:
            return "❌ Error: rate_kbps must be a positive integer"

        # Convert rate from Kbps to bits per second
        # rate_kbps (Kbps) -> rate_bps (bits per second): rate_kbps * 1000
        # burst_bytes stays as is (bytes)
        rate_bps = int(rate_kbps * 1000)

        # Use provided URL or default
        if vmanage_url and vmanage_url.strip():
            url = vmanage_url.strip()
            url = url.replace("https://", "").replace("http://", "")
            if ":" in url:
                host, port = url.split(":", 1)
            else:
                host = url
                port = VMANAGE_PORT
            api = CiscoSDWANAPI(host, port, VMANAGE_USERNAME, VMANAGE_PASSWORD, VMANAGE_VERIFY_SSL)
        else:
            api = sdwan_api

        await api.authenticate()

        output = f"""🔧 QoS Policer Update

{'='*60}
🖥️  Device ID: {device_id}
📝 New Rate: {rate_kbps} Kbps ({rate_bps} bps)
📝 New Burst: {burst_bytes} bytes
{'='*60}

📋 Step 1: Locating device policy group...
"""

        # Step 1: Get all policy groups and find the one with this device
        policy_groups = await api.get_policy_groups()
        target_policy_group = None
        target_policy_group_name = None
        device_uuid = None  # Store the actual device UUID

        for pg in policy_groups:
            # API returns 'id' not 'policyGroupId'
            pg_id = pg.get('id') or pg.get('policyGroupId')
            pg_name = pg.get('name', 'Unknown')

            if not pg_id:
                continue

            try:
                associations = await api.get_policy_group_device_associations(pg_id)

                for assoc in associations:
                    device_ip = assoc.get('deviceIP')

                    # Check if deviceIP (system IP) matches the provided device_id
                    if device_ip == device_id:
                        target_policy_group = pg_id
                        target_policy_group_name = pg_name
                        device_uuid = assoc.get('id')  # Capture the device UUID for deployment
                        output += f"✅ Found policy group: {pg_name}\n"
                        output += f"✅ Found device UUID: {device_uuid}\n"
                        break

                if target_policy_group:
                    break
            except Exception as e:
                logger.warning(f"Error checking policy group {pg_id}: {e}")
                continue

        if not target_policy_group:
            return output + f"\n❌ Error: Device {device_id} not found in any policy group"

        if not device_uuid:
            return output + f"\n❌ Error: Device UUID not found for {device_id}"

        # Step 2: Get policy group details and find application-priority profile
        output += f"\n📋 Step 2: Retrieving application-priority profile...\n"
        pg_details = await api.get_policy_group_details(target_policy_group)

        profiles = pg_details.get('profiles', [])
        app_priority_profile = None

        for profile in profiles:
            if profile.get('type') == 'application-priority':
                app_priority_profile = profile
                break

        if not app_priority_profile:
            return output + f"\n❌ Error: No application-priority profile found for this device"

        profile_id = app_priority_profile.get('id')

        # Step 3: Get application-priority profile details and find policer
        output += f"📋 Step 3: Locating policer configuration...\n"
        app_priority_details = await api.get_application_priority_profile(profile_id)

        # Find policer in associatedProfileParcels -> traffic-policy -> subparcels
        associated_parcels = app_priority_details.get('associatedProfileParcels', [])
        policer_parcel = None

        # Look through associatedProfileParcels to find traffic-policy, then search its subparcels
        for parcel in associated_parcels:
            if parcel.get('parcelType') == 'traffic-policy':
                subparcels = parcel.get('subparcels', [])

                for subparcel in subparcels:
                    if subparcel.get('parcelType') == 'policer':
                        policer_parcel = subparcel
                        break

                if policer_parcel:
                    break

        if not policer_parcel:
            return output + f"\n❌ Error: No policer configuration found"

        list_object_id = policer_parcel.get('parcelId')

        # Step 4: Get policy object profile ID
        output += f"📋 Step 4: Finding Default_Policy_Object_Profile...\n"
        policy_object_profiles = await api.get_policy_object_profiles()

        # DEBUG: Log all available policy object profiles
        logger.info(f"Available policy object profiles: {json.dumps(policy_object_profiles, indent=2)}")

        policy_object_id = None
        for profile in policy_object_profiles:
            profile_name = profile.get('profileName', profile.get('name', ''))
            profile_id = profile.get('profileId', profile.get('id', ''))
            logger.info(f"Checking policy object profile: name='{profile_name}', id='{profile_id}'")
            if profile_name == 'Default_Policy_Object_Profile':
                policy_object_id = profile_id
                break

        if not policy_object_id:
            # Show available profiles in error message
            available_names = [p.get('profileName', p.get('name', 'Unknown')) for p in policy_object_profiles]
            return output + f"\n❌ Error: Default_Policy_Object_Profile not found\n   Available profiles: {', '.join(available_names)}"

        output += f"✅ Found policy object profile ID: {policy_object_id}\n"

        # Step 5: Get current QoS policy configuration
        output += f"📋 Step 5: Retrieving current policer configuration...\n"
        qos_details = await api.get_qos_policy_details(profile_id, list_object_id)

        # DEBUG: Log the full response structure
        logger.info(f"QoS details response structure: {json.dumps(qos_details, indent=2)}")

        # Extract current values
        payload = qos_details.get('payload', {})
        data = payload.get('data', {})
        entries = data.get('entries', [])
        policer_name = payload.get('name', 'Unknown')

        if not entries:
            return output + f"\n❌ Error: No policer entries found"

        current_entry = entries[0]
        old_rate_bps = current_entry.get('rate', {}).get('value', 0)
        old_burst_bytes = current_entry.get('burst', {}).get('value', 0)
        exceed_action = current_entry.get('exceed', {}).get('value', 'drop')

        # Calculate display values for current config
        # Rate: bits per second -> Kbps
        # Burst: bytes (no conversion)
        old_rate_kbps = old_rate_bps / 1000

        output += f"""✅ Current configuration retrieved
   • Current Rate: {old_rate_kbps:.2f} Kbps ({old_rate_bps} bps)
   • Current Burst: {old_burst_bytes} bytes
   • Exceed Action: {exceed_action}

📋 Step 6: Preparing updated configuration...
"""

        # Step 6: Prepare updated payload
        # Use the entire payload from GET response and only modify the values we need
        import copy

        # Deep copy the entire payload structure to preserve all fields
        updated_payload = copy.deepcopy(payload)

        # Update only the burst and rate values in the entries array
        # Rate: bits per second, Burst: bytes
        updated_payload['data']['entries'][0]['burst']['value'] = burst_bytes
        updated_payload['data']['entries'][0]['rate']['value'] = rate_bps

        # DEBUG: Log the payload being sent
        logger.info(f"PUT payload structure: {json.dumps(updated_payload, indent=2)}")

        # Step 7: Apply the update using the policy-object endpoint
        output += f"📋 Step 7: Applying configuration update via policy-object endpoint...\n"
        await api.update_policer_via_policy_object(policy_object_id, list_object_id, updated_payload)

        output += f"""✅ Configuration updated successfully

📋 Step 8: Deploying policy group to device...\n"""

        # Step 8: Deploy the policy group to the device using device UUID
        await api.deploy_policy_group(target_policy_group, [device_uuid])

        output += f"""
{'='*60}
✅ QoS Policer Updated and Deployed Successfully!
{'='*60}

📊 Configuration Changes:

🏷️  Policy Group: {target_policy_group_name}
🏷️  Policer: {policer_name}
📱 Device: {device_id}

📈 Before → After:
   • Rate:   {old_rate_kbps:.2f} Kbps ({old_rate_bps} bps) → {rate_kbps} Kbps ({rate_bps} bps)
   • Burst:  {old_burst_bytes} bytes → {burst_bytes} bytes
   • Exceed: {exceed_action} (unchanged)

{'='*60}

✅ Configuration has been applied and deployed to vManage
💡 The policy group has been deployed to the device
💡 You can monitor deployment progress in the vManage UI
"""

        return output

    except Exception as e:
        logger.error(f"Error updating QoS policer: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def deploy_policy_group(
    policy_group_name: str,
    device_ids: str,
    vmanage_url: Optional[str] = None
) -> str:
    """
    Deploy a policy group to selected devices.

    Args:
        policy_group_name: Name of the policy group to deploy
        device_ids: Comma-separated list of device system IPs to deploy to (e.g., "10.255.255.18,10.255.255.19")
                   The function will automatically look up the corresponding device UUIDs
        vmanage_url: Optional vManage URL (uses environment variable if not provided)

    Returns:
        Deployment status message
    """
    try:
        # Initialize API client
        api = CiscoSDWANAPI(base_url=vmanage_url) if vmanage_url else sdwan_api

        output = f"""
🚀 Policy Group Deployment
{'='*60}
🏷️  Policy Group: {policy_group_name}
📱 Target Devices: {device_ids.replace(',', ', ')}
{'='*60}

"""

        # Parse device IDs
        device_id_list = [d.strip() for d in device_ids.split(',')]

        # Step 1: Find the policy group ID
        output += f"📋 Step 1: Finding policy group '{policy_group_name}'...\n"
        policy_groups = await api.get_policy_groups()

        target_policy_group_id = None
        for pg in policy_groups:
            pg_id = pg.get('id') or pg.get('policyGroupId')
            pg_name = pg.get('name', 'Unknown')

            if pg_name == policy_group_name:
                target_policy_group_id = pg_id
                break

        if not target_policy_group_id:
            return output + f"\n❌ Error: Policy group '{policy_group_name}' not found"

        output += f"✅ Found policy group ID: {target_policy_group_id}\n"

        # Step 2: Look up device UUIDs from system IPs
        output += f"\n📋 Step 2: Looking up device UUIDs from system IPs...\n"

        # Get device associations for this policy group
        associations = await api.get_policy_group_device_associations(target_policy_group_id)

        # Build a mapping of deviceIP -> device UUID
        device_ip_to_uuid = {}
        for assoc in associations:
            device_ip = assoc.get('deviceIP')
            device_uuid = assoc.get('id')
            if device_ip and device_uuid:
                device_ip_to_uuid[device_ip] = device_uuid

        # Convert system IPs to UUIDs
        device_uuid_list = []
        not_found = []
        for system_ip in device_id_list:
            if system_ip in device_ip_to_uuid:
                device_uuid_list.append(device_ip_to_uuid[system_ip])
                output += f"✅ Found UUID for {system_ip}: {device_ip_to_uuid[system_ip]}\n"
            else:
                not_found.append(system_ip)

        if not_found:
            return output + f"\n❌ Error: Could not find device UUIDs for: {', '.join(not_found)}"

        if not device_uuid_list:
            return output + f"\n❌ Error: No valid device UUIDs found"

        # Step 3: Deploy to devices using UUIDs
        output += f"\n📋 Step 3: Deploying policy group to {len(device_uuid_list)} device(s)...\n"
        await api.deploy_policy_group(target_policy_group_id, device_uuid_list)

        output += f"""
{'='*60}
✅ Policy Group Deployment Initiated!
{'='*60}

📊 Deployment Details:
   • Policy Group: {policy_group_name}
   • Devices: {len(device_id_list)}
   • Status: Initiated

{'='*60}

✅ Deployment request has been sent to vManage
💡 You can monitor the deployment progress in the vManage UI
"""

        return output

    except Exception as e:
        logger.error(f"Error deploying policy group: {e}")
        return f"❌ Error: {str(e)}"

# ---- Server Startup ----
if __name__ == "__main__":
    print("🚀 Starting Cisco Catalyst SD-WAN MCP Server...")
    
    # Test vManage API connectivity
    try:
        import asyncio
        
        async def test_connection():
            await sdwan_api.authenticate()
            devices = await sdwan_api.get_devices()
            return len(devices)
        
        device_count = asyncio.run(test_connection())
        print(f"✅ Successfully connected to vManage API")
        print(f"📊 Found {device_count} devices in SD-WAN fabric")
    except Exception as e:
        print(f"❌ Failed to connect to vManage API: {e}")
        print("💡 Please check your vManage credentials, host connectivity, and API access")
        print("💡 Ensure the vManage REST API is enabled and accessible")
        sys.exit(1)
    
    # Start the MCP server
    print(f"🌐 MCP Server starting on {mcp_host}:{mcp_port}")

    # List all registered tools
    print(f"\n📋 Registered MCP Tools:")
    print(f"   - get_software_versions")
    print(f"   - get_device_details")
    print(f"   - get_version_compliance")
    print(f"   - get_device_health")
    print(f"   - get_control_connections")
    print(f"   - get_bfd_sessions")
    print(f"   - get_interfaces")
    print(f"   - get_bgp_monitoring")
    print(f"   - get_omp_monitoring")
    print(f"   - get_configuration_groups")
    print(f"   - get_application_health")
    print(f"   - start_nwpi_trace")
    print(f"   - analyze_nwpi_trace")
    print(f"   - get_qos_configuration ✨ NEW")
    print(f"   - update_qos_policer ✨ NEW")
    print(f"\n✅ Total: 15 tools available\n")

    mcp.run(transport="http", host=mcp_host, port=mcp_port)
