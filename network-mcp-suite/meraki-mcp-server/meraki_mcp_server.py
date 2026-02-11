#!/usr/bin/env python3
"""
Cisco Meraki MCP Server

A Model Context Protocol (MCP) server that provides access to Cisco Meraki
Dashboard API functionality. This server allows AI assistants and other MCP clients
to interact with Cisco Meraki for network monitoring, device management, and security analysis.

Features:
- List organizations and networks
- Monitor device status with detailed metrics
- Track client connectivity and wireless events
- Analyze firewall rules (L3 and L7)
- Review security events
- Automatic pagination for large datasets
- Rate limiting to respect API constraints
- Dual-mode operation (single network or all networks)
- Bearer token authentication

Environment Variables:
- MERAKI_API_KEY: Required. Your Meraki Dashboard API Key
- MERAKI_BASE_URL: Optional. API base URL. Defaults to https://api.meraki.com/api/v1
- MCP_PORT: Optional. Port for MCP server. Defaults to 8000
- MCP_HOST: Optional. Host for MCP server. Defaults to localhost

Author: Ricardo Kaufmann
Based on: Cisco Meraki Dashboard API v1
"""

import os
import sys
import json
import logging
import httpx
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta, timezone
from fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("meraki-server")

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
MERAKI_API_KEY = os.getenv("MERAKI_API_KEY")
MERAKI_BASE_URL = os.getenv("MERAKI_BASE_URL", "https://api.meraki.com/api/v1")
mcp_host = os.getenv("MCP_HOST", "localhost")
mcp_port = int(os.getenv("MCP_PORT", "8000"))

# Validate required environment variables
if not MERAKI_API_KEY:
    raise ValueError("MERAKI_API_KEY environment variable is required")

print(f"🌐 Meraki API: {MERAKI_BASE_URL}")
print(f"🔑 API Key: {MERAKI_API_KEY[:8]}...")
print(f"🚀 Starting MCP server on {mcp_host}:{mcp_port}")


class CiscoMerakiAPI:
    """Cisco Meraki Dashboard REST API client"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.rate_limit_delay = 0.2  # 200ms between requests to respect rate limits
        self.last_request_time = 0
        
        logger.info(f"Initialized Meraki API client for {self.base_url}")
    
    async def _rate_limit(self):
        """Implement rate limiting between requests"""
        current_time = asyncio.get_event_loop().time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last_request)
        
        self.last_request_time = asyncio.get_event_loop().time()
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None, 
        data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make an authenticated API request with rate limiting"""
        await self._rate_limit()
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            logger.info(f"Making {method} request to {url}")
            
            try:
                if method.upper() == 'GET':
                    response = await client.get(url, headers=headers, params=params)
                elif method.upper() == 'POST':
                    response = await client.post(url, headers=headers, json=data)
                elif method.upper() == 'PUT':
                    response = await client.put(url, headers=headers, json=data)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                if response.status_code in [200, 201]:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limit exceeded, wait and retry
                    retry_after = int(response.headers.get('Retry-After', 1))
                    logger.warning(f"Rate limit exceeded, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    return await self._make_request(method, endpoint, params, data)
                else:
                    raise Exception(f"API request failed: {response.status_code} - {response.text}")
            except httpx.TimeoutException:
                raise Exception("Request timeout - Meraki API took too long to respond")
    
    async def _paginated_request(
        self, 
        endpoint: str, 
        params: Optional[Dict] = None,
        per_page: int = 1000
    ) -> List[Dict[str, Any]]:
        """Make paginated requests to handle large datasets"""
        all_results = []
        starting_after = None
        
        if params is None:
            params = {}
        
        params['perPage'] = per_page
        
        while True:
            if starting_after:
                params['startingAfter'] = starting_after
            
            results = await self._make_request('GET', endpoint, params=params)
            
            if isinstance(results, list):
                if not results:
                    break
                all_results.extend(results)
                
                # Check if there are more pages
                if len(results) < per_page:
                    break
                
                # Use the last item's ID for pagination
                if 'id' in results[-1]:
                    starting_after = results[-1]['id']
                elif 'serial' in results[-1]:
                    starting_after = results[-1]['serial']
                else:
                    break
            else:
                # Not a list, return as is
                return results
        
        return all_results
    
    # ---- Organizations ----
    async def get_organizations(self) -> List[Dict[str, Any]]:
        """Get all organizations the API key has access to"""
        return await self._make_request('GET', '/organizations')
    
    # ---- Networks ----
    async def get_organization_networks(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get all networks in an organization"""
        return await self._paginated_request(f'/organizations/{organization_id}/networks')
    
    # ---- Devices ----
    async def get_organization_devices(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get all devices in an organization"""
        return await self._paginated_request(f'/organizations/{organization_id}/devices')
    
    async def get_network_devices(self, network_id: str) -> List[Dict[str, Any]]:
        """Get devices in a specific network"""
        return await self._make_request('GET', f'/networks/{network_id}/devices')
    
    async def get_organization_device_statuses(
        self, 
        organization_id: str,
        network_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get device statuses for organization with detailed metrics"""
        params = {}
        if network_ids:
            params['networkIds[]'] = network_ids
        
        return await self._paginated_request(
            f'/organizations/{organization_id}/devices/statuses',
            params=params
        )
    
    async def get_device_clients(self, serial: str, timespan: int = 86400) -> List[Dict[str, Any]]:
        """Get clients for a specific device (timespan in seconds, default 24h)"""
        params = {'timespan': timespan}
        return await self._make_request('GET', f'/devices/{serial}/clients', params=params)
    
    # ---- Clients ----
    async def get_network_clients(
        self, 
        network_id: str, 
        timespan: int = 86400
    ) -> List[Dict[str, Any]]:
        """Get clients in a network (timespan in seconds, default 24h)"""
        params = {'timespan': timespan}
        return await self._paginated_request(f'/networks/{network_id}/clients', params=params)
    
    # ---- Wireless ----
    async def get_network_ssids(self, network_id: str) -> List[Dict[str, Any]]:
        """Get SSIDs configured in a network"""
        return await self._make_request('GET', f'/networks/{network_id}/wireless/ssids')
    
    async def get_wireless_client_connectivity_events(
        self,
        network_id: str,
        client_id: str,
        timespan: int = 86400,
        per_page: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get wireless client connectivity events for a specific client (timespan in seconds, default 24h)"""
        params = {
            'timespan': timespan,
            'perPage': per_page
        }
        return await self._paginated_request(
            f'/networks/{network_id}/wireless/clients/{client_id}/connectivityEvents',
            params=params
        )
    
    async def get_wireless_signal_quality_by_client(
        self,
        organization_id: str,
        timespan: int = 86400
    ) -> List[Dict[str, Any]]:
        """Get wireless signal quality by client for organization (timespan in seconds, default 24h)"""
        params = {'timespan': timespan}
        return await self._paginated_request(
            f'/organizations/{organization_id}/wireless/devices/signalQuality/byClient',
            params=params
        )
    
    # ---- Firewall ----
    async def get_network_appliance_firewall_l3_rules(
        self, 
        network_id: str
    ) -> Dict[str, Any]:
        """Get L3 firewall rules for a network"""
        return await self._make_request(
            'GET',
            f'/networks/{network_id}/appliance/firewall/l3FirewallRules'
        )
    
    async def get_network_appliance_firewall_l7_rules(
        self, 
        network_id: str
    ) -> Dict[str, Any]:
        """Get L7 firewall rules for a network"""
        return await self._make_request(
            'GET',
            f'/networks/{network_id}/appliance/firewall/l7FirewallRules'
        )
    
    # ---- Security Events ----
    async def get_network_appliance_security_events(
        self,
        network_id: str,
        timespan: int = 86400,
        per_page: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get security events for a network (timespan in seconds, default 24h)"""
        params = {
            'timespan': timespan,
            'perPage': per_page
        }
        return await self._paginated_request(
            f'/networks/{network_id}/appliance/security/events',
            params=params
        )


# Initialize API client
meraki_api = CiscoMerakiAPI(MERAKI_BASE_URL, MERAKI_API_KEY)

# Initialize FastMCP server
mcp = FastMCP("Cisco Meraki MCP Server")


# ---- Helper Functions ----

def get_status_emoji(status: str) -> str:
    """Get emoji for device status"""
    status_lower = status.lower() if status else ""
    if status_lower in ['online', 'active', 'up', 'connected']:
        return "🟢"
    elif status_lower in ['offline', 'down', 'disconnected']:
        return "🔴"
    elif status_lower in ['alerting', 'warning']:
        return "🟡"
    elif status_lower in ['dormant', 'inactive']:
        return "⚫"
    else:
        return "⚪"


def format_bytes(bytes_value: Optional[int]) -> str:
    """Format bytes into human-readable string"""
    if bytes_value is None:
        return "N/A"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def format_timestamp(ts: Optional[str]) -> str:
    """Format ISO timestamp to readable format"""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return ts


# ---- MCP Tools ----

@mcp.tool()
async def get_organizations() -> str:
    """
    List all Cisco Meraki organizations that the API key has access to.
    
    Retrieves a list of all organizations, including their IDs and names.
    This is typically the first call to make when exploring a Meraki environment.
    
    Returns:
        Formatted string containing:
        - Total count of organizations
        - List of organizations with IDs and names
    """
    logger.info("Executing get_organizations")
    
    try:
        orgs = await meraki_api.get_organizations()
        
        output = f"""✅ Cisco Meraki Organizations

📊 Summary:
- Total Organizations: {len(orgs)}

{'='*60}
🏢 ORGANIZATIONS
{'='*60}
"""
        
        for org in orgs:
            org_id = org.get('id', 'N/A')
            org_name = org.get('name', 'N/A')
            output += f"\n   🏢 {org_name}\n      🆔 ID: {org_id}"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting organizations: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_organization_networks(organization_id: str) -> str:
    """
    List all networks in a Cisco Meraki organization.
    
    Retrieves comprehensive information about all networks within an organization,
    including network types, product types, and timezone information.
    
    Args:
        organization_id: The Meraki organization ID
    
    Returns:
        Formatted string containing:
        - Total count of networks
        - Network details (ID, name, type, products, timezone)
    """
    logger.info(f"Executing get_organization_networks for org: {organization_id}")
    
    try:
        networks = await meraki_api.get_organization_networks(organization_id)
        
        # Count by type
        type_counts = {}
        for net in networks:
            net_type = net.get('type', 'unknown')
            type_counts[net_type] = type_counts.get(net_type, 0) + 1
        
        output = f"""✅ Cisco Meraki Networks

📊 Summary:
- Organization ID: {organization_id}
- Total Networks: {len(networks)}

📈 Networks by Type:"""
        
        for net_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            output += f"\n- {net_type}: {count}"
        
        output += f"""

{'='*60}
🌐 NETWORKS
{'='*60}
"""
        
        for network in networks:
            net_id = network.get('id', 'N/A')
            net_name = network.get('name', 'N/A')
            net_type = network.get('type', 'N/A')
            products = ', '.join(network.get('productTypes', []))
            timezone = network.get('timeZone', 'N/A')
            
            output += f"""
   🌐 {net_name}
      🆔 ID: {net_id}
      📋 Type: {net_type}
      📦 Products: {products}
      🕐 Timezone: {timezone}"""
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting networks: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_devices(
    network_id: Optional[str] = None,
    organization_id: Optional[str] = None
) -> str:
    """
    Get devices in a specific network or all networks in an organization.
    
    Retrieves device information including model, serial number, MAC address,
    firmware version, and network assignment. Supports dual-mode operation:
    single network or all networks in an organization.
    
    Args:
        network_id: Specific network ID (optional, for single network mode)
        organization_id: Organization ID (required if network_id not provided)
    
    Returns:
        Formatted string containing:
        - Total device count
        - Device details by network
        - Model and product type distribution
    """
    logger.info(f"Executing get_network_devices - network: {network_id}, org: {organization_id}")
    
    try:
        if network_id:
            # Single network mode
            devices = await meraki_api.get_network_devices(network_id)
            output = f"""✅ Cisco Meraki Network Devices

📊 Summary:
- Network ID: {network_id}
- Total Devices: {len(devices)}
"""
        elif organization_id:
            # All networks mode
            devices = await meraki_api.get_organization_devices(organization_id)
            output = f"""✅ Cisco Meraki Organization Devices

📊 Summary:
- Organization ID: {organization_id}
- Total Devices: {len(devices)}
"""
        else:
            return "❌ Error: Either network_id or organization_id must be provided"
        
        # Count by product type
        product_counts = {}
        model_counts = {}
        for dev in devices:
            product = dev.get('productType', 'unknown')
            model = dev.get('model', 'unknown')
            product_counts[product] = product_counts.get(product, 0) + 1
            model_counts[model] = model_counts.get(model, 0) + 1
        
        output += """
📈 Devices by Product Type:"""
        for product, count in sorted(product_counts.items(), key=lambda x: x[1], reverse=True):
            output += f"\n- {product}: {count}"
        
        output += f"""

{'='*60}
📱 DEVICES
{'='*60}
"""
        
        for device in devices[:50]:  # Limit to first 50 for readability
            name = device.get('name', 'Unnamed')
            serial = device.get('serial', 'N/A')
            model = device.get('model', 'N/A')
            mac = device.get('mac', 'N/A')
            lan_ip = device.get('lanIp', 'N/A')
            firmware = device.get('firmware', 'N/A')
            net_id = device.get('networkId', 'N/A')
            
            output += f"""
   📱 {name}
      🆔 Serial: {serial}
      📦 Model: {model}
      🌐 MAC: {mac}
      🔌 LAN IP: {lan_ip}
      💾 Firmware: {firmware}
      🌐 Network: {net_id}"""
        
        if len(devices) > 50:
            output += f"\n\n   ℹ️  Showing 50 of {len(devices)} devices. Use filters or specific network_id to narrow results."
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_organization_devices(organization_id: str) -> str:
    """
    Get all devices across all networks in an organization.
    
    Retrieves comprehensive device inventory for an entire organization,
    including all networks and their devices.
    
    Args:
        organization_id: The Meraki organization ID
    
    Returns:
        Formatted string containing:
        - Total device count across organization
        - Device distribution by product type and model
        - Detailed device information
    """
    logger.info(f"Executing get_organization_devices for org: {organization_id}")
    
    # This uses the same implementation as get_network_devices with org mode
    return await get_network_devices(organization_id=organization_id)


@mcp.tool()
async def get_device_statuses(
    organization_id: str,
    network_ids: Optional[str] = None
) -> str:
    """
    Get detailed device status information with performance metrics.
    
    Retrieves comprehensive status information for all devices in an organization,
    including online/offline status, performance metrics, uplink information,
    and client counts. Optionally filter by specific networks.
    
    Args:
        organization_id: The Meraki organization ID
        network_ids: Comma-separated network IDs to filter (optional)
    
    Returns:
        Formatted string containing:
        - Device status summary (online, offline, alerting)
        - Detailed metrics per device (uplink status, client count, traffic)
        - Performance indicators and alerts
    """
    logger.info(f"Executing get_device_statuses for org: {organization_id}")
    
    try:
        network_id_list = None
        if network_ids:
            network_id_list = [nid.strip() for nid in network_ids.split(',')]
        
        statuses = await meraki_api.get_organization_device_statuses(
            organization_id,
            network_ids=network_id_list
        )
        
        # Count by status
        status_counts = {'online': 0, 'offline': 0, 'alerting': 0, 'dormant': 0}
        for status in statuses:
            stat = status.get('status', 'unknown').lower()
            if stat in status_counts:
                status_counts[stat] += 1
        
        output = f"""✅ Cisco Meraki Device Statuses

📊 Summary:
- Organization ID: {organization_id}
- Total Devices: {len(statuses)}

📈 Status Distribution:
- 🟢 Online: {status_counts['online']}
- 🔴 Offline: {status_counts['offline']}
- 🟡 Alerting: {status_counts['alerting']}
- ⚫ Dormant: {status_counts['dormant']}

{'='*60}
📊 DEVICE STATUS DETAILS
{'='*60}
"""
        
        for device in statuses[:30]:  # Limit to first 30
            name = device.get('name', 'Unnamed')
            serial = device.get('serial', 'N/A')
            status = device.get('status', 'unknown')
            status_emoji = get_status_emoji(status)
            model = device.get('model', 'N/A')
            product_type = device.get('productType', 'N/A')
            last_reported = format_timestamp(device.get('lastReportedAt'))
            public_ip = device.get('publicIp', 'N/A')
            
            output += f"""
   {status_emoji} {name}
      🆔 Serial: {serial}
      📦 Model: {model} ({product_type})
      📡 Status: {status.upper()}
      🕐 Last Reported: {last_reported}
      🌐 Public IP: {public_ip}"""
            
            # Network info
            network_id = device.get('networkId', 'N/A')
            output += f"\n      🌐 Network ID: {network_id}"
            
            # Gateway info (if applicable)
            gateway = device.get('gateway', 'N/A')
            if gateway and gateway != 'N/A':
                output += f"\n      🚪 Gateway: {gateway}"
            
            # IP configuration
            ip_type = device.get('ipType', 'N/A')
            primary_dns = device.get('primaryDns', 'N/A')
            if ip_type != 'N/A':
                output += f"\n      🔌 IP Type: {ip_type}"
            if primary_dns != 'N/A':
                output += f"\n      🌐 Primary DNS: {primary_dns}"
            
            # Performance metrics
            performance = device.get('performance', {})
            if performance:
                perf_score = performance.get('perfScore', 'N/A')
                if perf_score != 'N/A':
                    output += f"\n      ⚡ Performance Score: {perf_score}"
            
            # Components (like power supplies, fans)
            components = device.get('components', {})
            if components:
                power_supplies = components.get('powerSupplies', [])
                if power_supplies:
                    output += f"\n      🔌 Power Supplies: {len(power_supplies)}"
                    for ps in power_supplies:
                        ps_status = ps.get('status', 'unknown')
                        ps_emoji = get_status_emoji(ps_status)
                        output += f"\n         {ps_emoji} Slot: {ps.get('slot', 'N/A')} - {ps_status}"
        
        if len(statuses) > 30:
            output += f"\n\n   ℹ️  Showing 30 of {len(statuses)} devices. Use network_ids filter to narrow results."
        
        # Health summary
        health_pct = (status_counts['online'] / len(statuses) * 100) if len(statuses) > 0 else 0
        output += f"""

{'='*60}
💊 HEALTH SUMMARY
{'='*60}

   📊 Overall Health: {health_pct:.1f}% online"""
        
        if status_counts['alerting'] > 0:
            output += f"\n   ⚠️  {status_counts['alerting']} device(s) reporting alerts"
        if status_counts['offline'] > 0:
            output += f"\n   ⚠️  {status_counts['offline']} device(s) offline"
        
        if health_pct >= 95:
            output += "\n   ✅ Network health is excellent"
        elif health_pct >= 85:
            output += "\n   ⚠️  Network health is good but could be improved"
        else:
            output += "\n   ❌ Network health requires attention"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting device statuses: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_clients(
    network_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    timespan: int = 86400
) -> str:
    """
    Get clients connected to a network or all networks in an organization.
    
    Retrieves information about all clients (devices) connected to the network(s),
    including MAC addresses, IP addresses, usage statistics, and connection details.
    Supports dual-mode operation for single network or organization-wide view.
    
    Args:
        network_id: Specific network ID (optional, for single network mode)
        organization_id: Organization ID (required if network_id not provided)
        timespan: Time span in seconds for client data (default: 86400 = 24 hours)
    
    Returns:
        Formatted string containing:
        - Total client count
        - Client distribution by network
        - Connection details and usage statistics
    """
    logger.info(f"Executing get_network_clients - network: {network_id}, org: {organization_id}")
    
    try:
        if network_id:
            # Single network mode
            clients = await meraki_api.get_network_clients(network_id, timespan=timespan)
            output = f"""✅ Cisco Meraki Network Clients

📊 Summary:
- Network ID: {network_id}
- Timespan: {timespan // 3600} hours
- Total Clients: {len(clients)}
"""
        elif organization_id:
            # All networks mode
            networks = await meraki_api.get_organization_networks(organization_id)
            all_clients = []
            
            for network in networks:
                net_id = network.get('id')
                if not net_id:
                    continue
                
                try:
                    clients = await meraki_api.get_network_clients(net_id, timespan=timespan)
                    for client in clients:
                        client['_networkId'] = net_id
                        client['_networkName'] = network.get('name', 'Unknown')
                    all_clients.extend(clients)
                except Exception as e:
                    logger.warning(f"Could not get clients for network {net_id}: {e}")
                    continue
            
            clients = all_clients
            output = f"""✅ Cisco Meraki Organization Clients

📊 Summary:
- Organization ID: {organization_id}
- Timespan: {timespan // 3600} hours
- Total Clients: {len(clients)}
- Networks Scanned: {len(networks)}
"""
        else:
            return "❌ Error: Either network_id or organization_id must be provided"
        
        # Analyze clients
        total_sent = sum(c.get('usage', {}).get('sent', 0) for c in clients)
        total_recv = sum(c.get('usage', {}).get('recv', 0) for c in clients)
        
        output += f"""
📊 Total Traffic:
- ⬆️  Sent: {format_bytes(total_sent)}
- ⬇️  Received: {format_bytes(total_recv)}

{'='*60}
👥 CLIENTS
{'='*60}
"""
        
        # Sort by usage (most active first)
        clients_sorted = sorted(
            clients, 
            key=lambda x: x.get('usage', {}).get('sent', 0) + x.get('usage', {}).get('recv', 0),
            reverse=True
        )
        
        for client in clients_sorted[:40]:  # Show top 40
            # Basic identification
            client_id = client.get('id', 'N/A')
            description = client.get('description', 'Unknown Device')
            mac = client.get('mac', 'N/A')
            
            # Network information
            ip = client.get('ip', 'N/A')
            ip6 = client.get('ip6', 'N/A')
            ip6_local = client.get('ip6Local', 'N/A')
            vlan = client.get('vlan', 'N/A')
            named_vlan = client.get('namedVlan', 'N/A')
            
            # Connection details
            ssid = client.get('ssid', 'N/A')
            switchport = client.get('switchport', 'N/A')
            status = client.get('status', 'N/A')
            
            # Device information
            manufacturer = client.get('manufacturer', 'N/A')
            os = client.get('os', 'N/A')
            device_type = client.get('deviceTypePrediction', 'N/A')
            wireless_cap = client.get('wirelessCapabilities', 'N/A')
            
            # User information
            user = client.get('user', 'N/A')
            notes = client.get('notes', 'N/A')
            
            # Usage statistics
            usage = client.get('usage', {})
            sent = format_bytes(usage.get('sent', 0))
            recv = format_bytes(usage.get('recv', 0))
            
            # Timestamps
            first_seen = client.get('firstSeen')
            last_seen = client.get('lastSeen')
            
            # Convert timestamps safely
            first_seen_str = 'N/A'
            last_seen_str = 'N/A'
            
            if first_seen:
                try:
                    if isinstance(first_seen, (int, float)):
                        first_seen_str = format_timestamp(datetime.fromtimestamp(first_seen, tz=timezone.utc).isoformat())
                    else:
                        first_seen_str = format_timestamp(first_seen)
                except:
                    first_seen_str = str(first_seen)
            
            if last_seen:
                try:
                    if isinstance(last_seen, (int, float)):
                        last_seen_str = format_timestamp(datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat())
                    else:
                        last_seen_str = format_timestamp(last_seen)
                except:
                    last_seen_str = str(last_seen)
            
            # Recent device information
            recent_device_mac = client.get('recentDeviceMac', 'N/A')
            recent_device_serial = client.get('recentDeviceSerial', 'N/A')
            recent_device_name = client.get('recentDeviceName', 'N/A')
            recent_device_connection = client.get('recentDeviceConnection', 'N/A')
            
            # Policy information
            adaptive_policy = client.get('adaptivePolicyGroup', 'N/A')
            group_policy = client.get('groupPolicy8021x', 'N/A')
            psk_group = client.get('pskGroup', 'N/A')
            
            # Systems Manager
            sm_installed = client.get('smInstalled', False)
            
            # Status emoji
            status_emoji = get_status_emoji(status)
            
            output += f"""
   {status_emoji} {description}
      🆔 Client ID: {client_id}
      🌐 MAC: {mac}
      👤 User: {user}
      
      📡 Network Information:
         🔌 IPv4: {ip}
         🔌 IPv6: {ip6}
         🔌 IPv6 Local: {ip6_local}
         📡 VLAN: {vlan}"""
            
            if named_vlan != 'N/A':
                output += f"\n         📛 VLAN Name: {named_vlan}"
            
            output += f"""
      
      🔗 Connection:
         📊 Status: {status}"""
            
            if ssid != 'N/A':
                output += f"\n         📶 SSID: {ssid}"
            if switchport != 'N/A':
                output += f"\n         🔌 Switch Port: {switchport}"
            
            output += f"\n         🔗 Connection Type: {recent_device_connection}"
            
            output += f"""
      
      🖥️  Device Information:
         🏭 Manufacturer: {manufacturer}
         💻 OS: {os}
         📱 Device Type: {device_type}"""
            
            if wireless_cap != 'N/A':
                output += f"\n         📡 Wireless: {wireless_cap}"
            
            output += f"""
      
      📊 Usage Statistics:
         ⬆️  Sent: {sent}
         ⬇️  Received: {recv}
      
      🕐 Timeline:
         🟢 First Seen: {first_seen_str}
         🔵 Last Seen: {last_seen_str}
      
      📱 Recent Device:
         🌐 MAC: {recent_device_mac}
         🆔 Serial: {recent_device_serial}
         📛 Name: {recent_device_name}"""
            
            # Policy information
            if adaptive_policy != 'N/A' or group_policy != 'N/A' or psk_group != 'N/A':
                output += "\n      \n      🔐 Policy & Security:"
                if adaptive_policy != 'N/A':
                    output += f"\n         🎯 Adaptive Policy: {adaptive_policy}"
                if group_policy != 'N/A':
                    output += f"\n         👥 Group Policy (802.1x): {group_policy}"
                if psk_group != 'N/A':
                    output += f"\n         🔑 PSK Group: {psk_group}"
            
            # Systems Manager
            if sm_installed:
                output += "\n      \n      📲 Systems Manager: Installed"
            
            # Notes
            if notes != 'N/A':
                output += f"\n      \n      📝 Notes: {notes}"
            
            # Show network for org-wide view
            if not network_id and '_networkName' in client:
                output += f"\n      \n      🌐 Network: {client['_networkName']}"
        
        if len(clients) > 40:
            output += f"\n\n   ℹ️  Showing top 40 of {len(clients)} clients by traffic usage."
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting clients: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_device_clients(serial: str, timespan: int = 86400) -> str:
    """
    Get clients connected to a specific device.
    
    Retrieves information about all clients connected to a particular device,
    useful for troubleshooting device-specific connectivity issues.
    
    Args:
        serial: Device serial number
        timespan: Time span in seconds for client data (default: 86400 = 24 hours)
    
    Returns:
        Formatted string containing:
        - Client count for the device
        - Client connection details
        - Usage statistics per client
    """
    logger.info(f"Executing get_device_clients for device: {serial}")
    
    try:
        clients = await meraki_api.get_device_clients(serial, timespan=timespan)
        
        output = f"""✅ Cisco Meraki Device Clients

📊 Summary:
- Device Serial: {serial}
- Timespan: {timespan // 3600} hours
- Total Clients: {len(clients)}

{'='*60}
👥 CLIENTS
{'='*60}
"""
        
        for client in clients:
            description = client.get('description', 'Unknown Device')
            mac = client.get('mac', 'N/A')
            ip = client.get('ip', 'N/A')
            usage = client.get('usage', {})
            sent = format_bytes(usage.get('sent', 0))
            recv = format_bytes(usage.get('recv', 0))
            
            output += f"""
   👤 {description}
      🌐 MAC: {mac}
      🔌 IP: {ip}
      ⬆️  Sent: {sent}
      ⬇️  Received: {recv}"""
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting device clients: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_ssids(
    network_id: Optional[str] = None,
    organization_id: Optional[str] = None
) -> str:
    """
    Get wireless SSIDs configured in a network or all networks.
    
    Retrieves SSID configuration including name, number, enabled status,
    authentication mode, and encryption settings. Supports dual-mode operation.
    
    Args:
        network_id: Specific network ID (optional, for single network mode)
        organization_id: Organization ID (required if network_id not provided)
    
    Returns:
        Formatted string containing:
        - SSID count
        - SSID configuration details (name, auth mode, encryption)
        - Enabled/disabled status
    """
    logger.info(f"Executing get_network_ssids - network: {network_id}, org: {organization_id}")
    
    try:
        if network_id:
            # Single network mode
            ssids = await meraki_api.get_network_ssids(network_id)
            output = f"""✅ Cisco Meraki Network SSIDs

📊 Summary:
- Network ID: {network_id}
- Total SSIDs: {len(ssids)}
"""
        elif organization_id:
            # All networks mode
            networks = await meraki_api.get_organization_networks(organization_id)
            all_ssids = []
            
            for network in networks:
                net_id = network.get('id')
                # Only get SSIDs for wireless networks
                product_types = network.get('productTypes', [])
                if 'wireless' not in product_types:
                    continue
                
                try:
                    ssids = await meraki_api.get_network_ssids(net_id)
                    for ssid in ssids:
                        ssid['_networkId'] = net_id
                        ssid['_networkName'] = network.get('name', 'Unknown')
                    all_ssids.extend(ssids)
                except Exception as e:
                    logger.warning(f"Could not get SSIDs for network {net_id}: {e}")
                    continue
            
            ssids = all_ssids
            output = f"""✅ Cisco Meraki Organization SSIDs

📊 Summary:
- Organization ID: {organization_id}
- Total SSIDs: {len(ssids)}
"""
        else:
            return "❌ Error: Either network_id or organization_id must be provided"
        
        # Count enabled/disabled
        enabled_count = sum(1 for s in ssids if s.get('enabled', False))
        disabled_count = len(ssids) - enabled_count
        
        output += f"""
📊 Status Distribution:
- 🟢 Enabled: {enabled_count}
- 🔴 Disabled: {disabled_count}

{'='*60}
📶 SSIDs
{'='*60}
"""
        
        for ssid in ssids:
            number = ssid.get('number', 'N/A')
            name = ssid.get('name', 'Unnamed')
            enabled = ssid.get('enabled', False)
            status_emoji = "🟢" if enabled else "🔴"
            auth_mode = ssid.get('authMode', 'N/A')
            encryption_mode = ssid.get('encryptionMode', 'N/A')
            visible = ssid.get('visible', True)
            
            output += f"""
   {status_emoji} SSID {number}: {name}
      📡 Status: {'Enabled' if enabled else 'Disabled'}
      🔐 Auth Mode: {auth_mode}
      🔒 Encryption: {encryption_mode}
      👁️  Visible: {'Yes' if visible else 'No (Hidden)'}"""
            
            # Show network for org-wide view
            if not network_id and '_networkName' in ssid:
                output += f"\n      🌐 Network: {ssid['_networkName']}"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting SSIDs: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_wireless_client_health(
    network_id: str,
    client_id: str,
    organization_id: str,
    timespan: int = 86400
) -> str:
    """
    Get comprehensive wireless client health information including RSSI and SNR.
    
    Retrieves detailed wireless health metrics for a specific client by combining
    connectivity events and signal quality data. Essential for diagnosing wireless
    performance and connectivity issues.
    
    Args:
        network_id: The network ID where the client is connected
        client_id: The client ID (MAC address) to query
        organization_id: The organization ID for signal quality data
        timespan: Time span in seconds (default: 86400 = 24 hours)
    
    Returns:
        Formatted string containing:
        - Connectivity events for the client
        - Signal quality metrics (RSSI, SNR) correlated by device
        - Overall wireless health assessment
    """
    logger.info(f"Executing get_wireless_client_health for client: {client_id} in network: {network_id}")
    
    try:
        # Fetch both APIs in parallel for efficiency
        connectivity_events_task = meraki_api.get_wireless_client_connectivity_events(
            network_id,
            client_id,
            timespan=timespan
        )
        signal_quality_task = meraki_api.get_wireless_signal_quality_by_client(
            organization_id,
            timespan=timespan
        )
        
        connectivity_events, all_signal_quality = await asyncio.gather(
            connectivity_events_task,
            signal_quality_task,
            return_exceptions=True
        )
        
        # Handle errors from API calls
        if isinstance(connectivity_events, Exception):
            logger.error(f"Error fetching connectivity events: {connectivity_events}")
            connectivity_events = []
        
        if isinstance(all_signal_quality, Exception):
            logger.error(f"Error fetching signal quality: {all_signal_quality}")
            all_signal_quality = []
        
        # Filter signal quality data for this specific client
        client_signal_quality = [
            sq for sq in all_signal_quality 
            if sq.get('clientId') == client_id or sq.get('clientMac') == client_id
        ]
        
        output = f"""✅ Cisco Meraki Wireless Client Health

📊 Summary:
- Network ID: {network_id}
- Client ID: {client_id}
- Timespan: {timespan // 3600} hours
- Connectivity Events: {len(connectivity_events)}
- Signal Quality Measurements: {len(client_signal_quality)}

{'='*60}
📡 SIGNAL QUALITY BY DEVICE
{'='*60}
"""
        
        # Group signal quality by device serial
        signal_by_device = {}
        for sq in client_signal_quality:
            device_serial = sq.get('deviceSerial', 'Unknown')
            if device_serial not in signal_by_device:
                signal_by_device[device_serial] = []
            signal_by_device[device_serial].append(sq)
        
        if signal_by_device:
            for device_serial, measurements in signal_by_device.items():
                # Calculate averages - Convert positive RSSI values to negative dBm
                rssi_raw = [m.get('rssi', 0) for m in measurements if m.get('rssi') is not None]
                # Convert positive RSSI to negative (API returns positive values)
                rssi_values = [-abs(r) for r in rssi_raw]
                snr_values = [m.get('snr', 0) for m in measurements if m.get('snr') is not None]
                
                avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else 0
                avg_snr = sum(snr_values) / len(snr_values) if snr_values else 0
                min_rssi = min(rssi_values) if rssi_values else 0
                max_rssi = max(rssi_values) if rssi_values else 0
                min_snr = min(snr_values) if snr_values else 0
                max_snr = max(snr_values) if snr_values else 0
                
                # Get additional info from first measurement
                first_measurement = measurements[0]
                ssid = first_measurement.get('ssid', 'N/A')
                band = first_measurement.get('band', 'N/A')
                channel = first_measurement.get('channel', 'N/A')
                
                # Signal quality assessment
                rssi_emoji = "🟢" if avg_rssi >= -60 else "🟡" if avg_rssi >= -70 else "🔴"
                snr_emoji = "🟢" if avg_snr >= 25 else "🟡" if avg_snr >= 15 else "🔴"
                
                output += f"""
   📱 Device: {device_serial}
      📶 SSID: {ssid}
      📡 Band: {band}
      📻 Channel: {channel}
      
      {rssi_emoji} RSSI (Signal Strength):
         📊 Average: {avg_rssi:.1f} dBm
         ⬆️  Best: {max_rssi:.1f} dBm
         ⬇️  Worst: {min_rssi:.1f} dBm
         📈 Measurements: {len(rssi_values)}
      
      {snr_emoji} SNR (Signal-to-Noise Ratio):
         📊 Average: {avg_snr:.1f} dB
         ⬆️  Best: {max_snr:.1f} dB
         ⬇️  Worst: {min_snr:.1f} dB
         📈 Measurements: {len(snr_values)}
"""
        else:
            output += "\n   ℹ️  No signal quality data available for this client in the specified timespan.\n"
        
        # Connectivity Events
        output += f"""
{'='*60}
🔗 CONNECTIVITY EVENTS
{'='*60}
"""
        
        if connectivity_events:
            # Group events by type
            event_types = {}
            for event in connectivity_events:
                event_type = event.get('type', 'Unknown')
                event_types[event_type] = event_types.get(event_type, 0) + 1
            
            output += "\n📊 Event Summary:"
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                output += f"\n   - {event_type}: {count}"
            
            output += "\n\n🕐 Recent Events (Last 20):\n"
            
            for event in connectivity_events[:20]:
                event_type = event.get('type', 'N/A')
                timestamp = format_timestamp(event.get('occurredAt'))
                device_serial = event.get('deviceSerial', 'N/A')
                ssid = event.get('ssid', 'N/A')
                band = event.get('band', 'N/A')
                channel = event.get('channel', 'N/A')
                rssi_raw = event.get('rssi', 'N/A')
                # Convert positive RSSI to negative dBm
                rssi = -abs(rssi_raw) if rssi_raw != 'N/A' and rssi_raw is not None else 'N/A'
                duration = event.get('durationMs', 'N/A')
                
                # Event type emoji
                event_emoji = "🟢" if event_type in ['association', 'auth'] else "🔴" if event_type in ['disassociation', 'deauth'] else "🟡"
                
                output += f"""
   {event_emoji} {event_type}
      🕐 Time: {timestamp}
      📱 Device: {device_serial}
      📶 SSID: {ssid}
      📡 Band: {band} | Channel: {channel}"""
                
                if rssi != 'N/A':
                    output += f"\n      📶 RSSI: {rssi:.1f} dBm"
                if duration != 'N/A':
                    output += f"\n      ⏱️  Duration: {duration} ms"
            
            if len(connectivity_events) > 20:
                output += f"\n\n   ℹ️  Showing 20 of {len(connectivity_events)} events."
        else:
            output += "\n   ℹ️  No connectivity events found for this client in the specified timespan.\n"
        
        # Health Assessment
        output += f"""

{'='*60}
💊 WIRELESS HEALTH ASSESSMENT
{'='*60}
"""
        
        if signal_by_device:
            # Overall health based on averages across all devices
            # Convert positive RSSI to negative dBm
            all_rssi_raw = [m.get('rssi', 0) for measurements in signal_by_device.values() 
                           for m in measurements if m.get('rssi') is not None]
            all_rssi = [-abs(r) for r in all_rssi_raw]
            all_snr = [m.get('snr', 0) for measurements in signal_by_device.values() 
                      for m in measurements if m.get('snr') is not None]
            
            overall_rssi = sum(all_rssi) / len(all_rssi) if all_rssi else 0
            overall_snr = sum(all_snr) / len(all_snr) if all_snr else 0
            
            health_issues = []
            
            if overall_rssi < -70:
                health_issues.append("⚠️  Weak signal strength (RSSI < -70 dBm)")
            if overall_snr < 15:
                health_issues.append("⚠️  High noise level (SNR < 15 dB)")
            
            # Check for frequent disconnections
            disconnect_types = ['disassociation', 'deauth', 'disconnect']
            disconnect_count = sum(1 for e in connectivity_events 
                                  if e.get('type', '').lower() in disconnect_types)
            
            if disconnect_count > 10:
                health_issues.append(f"⚠️  Frequent disconnections ({disconnect_count} in timespan)")
            
            if health_issues:
                output += "\n   ⚠️  Issues Detected:\n"
                for issue in health_issues:
                    output += f"      {issue}\n"
            else:
                output += "\n   ✅ Wireless health is good\n"
            
            # Recommendations
            output += "\n   💡 Signal Quality Guide:"
            output += "\n      RSSI: > -60 dBm (Excellent), -60 to -70 dBm (Good), < -70 dBm (Poor)"
            output += "\n      SNR:  > 25 dB (Excellent), 15-25 dB (Good), < 15 dB (Poor)"
        else:
            output += "\n   ℹ️  Unable to assess health - no signal quality data available.\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting wireless client health: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_appliance_firewall_l3_firewall_rules(
    network_id: Optional[str] = None,
    organization_id: Optional[str] = None
) -> str:
    """
    Get Layer 3 (IP-based) firewall rules for a network or all networks.
    
    Retrieves L3 firewall rules that control traffic based on IP addresses,
    ports, and protocols. Essential for security auditing and troubleshooting
    connectivity issues.
    
    Args:
        network_id: Specific network ID (optional, for single network mode)
        organization_id: Organization ID (required if network_id not provided)
    
    Returns:
        Formatted string containing:
        - Rule count
        - Detailed rule information (policy, protocol, ports, src/dst)
        - Default rule policy
    """
    logger.info(f"Executing get_network_appliance_firewall_l3_firewall_rules - network: {network_id}, org: {organization_id}")
    
    try:
        if network_id:
            # Single network mode
            result = await meraki_api.get_network_appliance_firewall_l3_rules(network_id)
            rules = result.get('rules', [])
            
            output = f"""✅ Cisco Meraki L3 Firewall Rules

📊 Summary:
- Network ID: {network_id}
- Total Rules: {len(rules)}
"""
        elif organization_id:
            # All networks mode
            networks = await meraki_api.get_organization_networks(organization_id)
            all_rules = []
            
            for network in networks:
                net_id = network.get('id')
                # Only get firewall rules for appliance networks
                product_types = network.get('productTypes', [])
                if 'appliance' not in product_types:
                    continue
                
                try:
                    result = await meraki_api.get_network_appliance_firewall_l3_rules(net_id)
                    rules = result.get('rules', [])
                    for rule in rules:
                        rule['_networkId'] = net_id
                        rule['_networkName'] = network.get('name', 'Unknown')
                    all_rules.extend(rules)
                except Exception as e:
                    logger.warning(f"Could not get L3 rules for network {net_id}: {e}")
                    continue
            
            rules = all_rules
            output = f"""✅ Cisco Meraki Organization L3 Firewall Rules

📊 Summary:
- Organization ID: {organization_id}
- Total Rules: {len(rules)}
"""
        else:
            return "❌ Error: Either network_id or organization_id must be provided"
        
        # Count by policy
        allow_count = sum(1 for r in rules if r.get('policy', '').lower() == 'allow')
        deny_count = sum(1 for r in rules if r.get('policy', '').lower() == 'deny')
        
        output += f"""
📊 Rule Distribution:
- 🟢 Allow: {allow_count}
- 🔴 Deny: {deny_count}

{'='*60}
🔒 FIREWALL RULES
{'='*60}
"""
        
        for idx, rule in enumerate(rules, 1):
            policy = rule.get('policy', 'N/A')
            protocol = rule.get('protocol', 'any')
            src_cidr = rule.get('srcCidr', 'any')
            src_port = rule.get('srcPort', 'any')
            dest_cidr = rule.get('destCidr', 'any')
            dest_port = rule.get('destPort', 'any')
            comment = rule.get('comment', '')
            
            policy_emoji = "🟢" if policy.lower() == 'allow' else "🔴"
            
            output += f"""
   {policy_emoji} Rule {idx}: {policy.upper()}
      📝 Comment: {comment if comment else 'No comment'}
      🌐 Protocol: {protocol}
      📍 Source: {src_cidr}:{src_port}
      🎯 Destination: {dest_cidr}:{dest_port}"""
            
            # Show network for org-wide view
            if not network_id and '_networkName' in rule:
                output += f"\n      🌐 Network: {rule['_networkName']}"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting L3 firewall rules: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_appliance_firewall_l7_firewall_rules(
    network_id: Optional[str] = None,
    organization_id: Optional[str] = None
) -> str:
    """
    Get Layer 7 (application-based) firewall rules for a network or all networks.
    
    Retrieves L7 firewall rules that control traffic based on application
    identification. Used for application-level filtering and bandwidth control.
    
    Args:
        network_id: Specific network ID (optional, for single network mode)
        organization_id: Organization ID (required if network_id not provided)
    
    Returns:
        Formatted string containing:
        - Rule count
        - Application-based rules with policies
        - Blocked/allowed applications
    """
    logger.info(f"Executing get_network_appliance_firewall_l7_firewall_rules - network: {network_id}, org: {organization_id}")
    
    try:
        if network_id:
            # Single network mode
            result = await meraki_api.get_network_appliance_firewall_l7_rules(network_id)
            rules = result.get('rules', [])
            
            output = f"""✅ Cisco Meraki L7 Firewall Rules

📊 Summary:
- Network ID: {network_id}
- Total Rules: {len(rules)}
"""
        elif organization_id:
            # All networks mode
            networks = await meraki_api.get_organization_networks(organization_id)
            all_rules = []
            
            for network in networks:
                net_id = network.get('id')
                # Only get firewall rules for appliance networks
                product_types = network.get('productTypes', [])
                if 'appliance' not in product_types:
                    continue
                
                try:
                    result = await meraki_api.get_network_appliance_firewall_l7_rules(net_id)
                    rules = result.get('rules', [])
                    for rule in rules:
                        rule['_networkId'] = net_id
                        rule['_networkName'] = network.get('name', 'Unknown')
                    all_rules.extend(rules)
                except Exception as e:
                    logger.warning(f"Could not get L7 rules for network {net_id}: {e}")
                    continue
            
            rules = all_rules
            output = f"""✅ Cisco Meraki Organization L7 Firewall Rules

📊 Summary:
- Organization ID: {organization_id}
- Total Rules: {len(rules)}
"""
        else:
            return "❌ Error: Either network_id or organization_id must be provided"
        
        # Count by policy
        deny_count = sum(1 for r in rules if r.get('policy', '').lower() == 'deny')
        
        output += f"""
📊 Rule Distribution:
- 🔴 Deny Rules: {deny_count}

{'='*60}
🔒 APPLICATION FIREWALL RULES
{'='*60}
"""
        
        for idx, rule in enumerate(rules, 1):
            policy = rule.get('policy', 'N/A')
            rule_type = rule.get('type', 'N/A')
            value = rule.get('value', 'N/A')
            
            policy_emoji = "🔴" if policy.lower() == 'deny' else "🟢"
            
            output += f"""
   {policy_emoji} Rule {idx}: {policy.upper()}
      📋 Type: {rule_type}
      🎯 Value: {value}"""
            
            # Show network for org-wide view
            if not network_id and '_networkName' in rule:
                output += f"\n      🌐 Network: {rule['_networkName']}"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting L7 firewall rules: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def get_network_appliance_security_events(
    network_id: str,
    timespan: int = 86400
) -> str:
    """
    Get security events from the MX security appliance.
    
    Retrieves security events including IDS/IPS alerts, malware detections,
    and other security-related incidents. Critical for security monitoring
    and incident response.
    
    Args:
        network_id: The network ID to query
        timespan: Time span in seconds (default: 86400 = 24 hours)
    
    Returns:
        Formatted string containing:
        - Event count and summary
        - Security event details with severity
        - Event types and priorities
    """
    logger.info(f"Executing get_network_appliance_security_events for network: {network_id}")
    
    try:
        events = await meraki_api.get_network_appliance_security_events(
            network_id,
            timespan=timespan
        )
        
        # Count by type
        event_types = {}
        priorities = {}
        for event in events:
            event_type = event.get('eventType', 'unknown')
            priority = event.get('priority', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
            priorities[priority] = priorities.get(priority, 0) + 1
        
        output = f"""✅ Cisco Meraki Security Events

📊 Summary:
- Network ID: {network_id}
- Timespan: {timespan // 3600} hours
- Total Events: {len(events)}

📊 Events by Type:"""
        
        for evt_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            output += f"\n- {evt_type}: {count}"
        
        output += """

📊 Events by Priority:"""
        for priority, count in sorted(priorities.items(), key=lambda x: x[1], reverse=True):
            output += f"\n- {priority}: {count}"
        
        output += f"""

{'='*60}
🛡️  SECURITY EVENTS
{'='*60}
"""
        
        for event in events[:50]:  # Show first 50
            event_type = event.get('eventType', 'N/A')
            timestamp = format_timestamp(event.get('ts'))
            src_ip = event.get('srcIp', 'N/A')
            dest_ip = event.get('destIp', 'N/A')
            protocol = event.get('protocol', 'N/A')
            priority = event.get('priority', 'N/A')
            message = event.get('message', 'N/A')
            
            priority_emoji = "🔴" if priority == 'high' else "🟡" if priority == 'medium' else "🟢"
            
            output += f"""
   {priority_emoji} {event_type}
      🕐 Time: {timestamp}
      📍 Source IP: {src_ip}
      🎯 Dest IP: {dest_ip}
      🌐 Protocol: {protocol}
      ⚠️  Priority: {priority}
      💬 Message: {message}"""
        
        if len(events) > 50:
            output += f"\n\n   ℹ️  Showing 50 of {len(events)} events."
        
        # Security summary
        high_priority = priorities.get('high', 0)
        if high_priority > 0:
            output += f"""

{'='*60}
⚠️  SECURITY ALERT
{'='*60}

   🔴 {high_priority} HIGH PRIORITY security event(s) detected!
   🛡️  Immediate investigation recommended"""
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting security events: {e}")
        return f"❌ Error: {str(e)}"


# ---- Server Startup ----
if __name__ == "__main__":
    print("🚀 Starting Cisco Meraki MCP Server...")
    
    # Test API connectivity
    try:
        async def test_connection():
            orgs = await meraki_api.get_organizations()
            return len(orgs)
        
        org_count = asyncio.run(test_connection())
        print(f"✅ Successfully connected to Meraki Dashboard API")
        print(f"📊 Found {org_count} organization(s)")
    except Exception as e:
        print(f"❌ Failed to connect to Meraki API: {e}")
        print("💡 Please check your API key and network connectivity")
        print("💡 Ensure your API key is valid and has the necessary permissions")
        sys.exit(1)
    
    # Start the MCP server
    print(f"🌐 MCP Server starting on {mcp_host}:{mcp_port}")
    mcp.run(transport="http", host=mcp_host, port=mcp_port)
