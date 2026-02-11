# Cisco Meraki MCP Server

A Model Context Protocol (MCP) server that provides AI assistants and other MCP clients with access to the Cisco Meraki Dashboard API. This server enables comprehensive network monitoring, device management, security analysis, and troubleshooting capabilities for Meraki deployments.

## 🌟 Features

- **Organization & Network Management**
  - List organizations and networks
  - View network topology and hierarchy
  
- **Device Monitoring**
  - Comprehensive device status with detailed metrics
  - Real-time health monitoring
  - Performance indicators
  - Uplink status tracking
  
- **Client Tracking**
  - Network-wide client visibility
  - Per-device client information
  - Usage statistics and traffic analysis
  
- **Wireless Management**
  - SSID configuration viewing
  - Wireless connectivity event tracking
  - Client roaming analysis
  
- **Security & Firewall**
  - Layer 3 (IP-based) firewall rules
  - Layer 7 (application-based) firewall rules
  - Security event monitoring
  - IDS/IPS alert tracking

- **Advanced Capabilities**
  - ✅ Automatic pagination for large datasets
  - ✅ Rate limiting to respect API constraints
  - ✅ Dual-mode operation (single network or organization-wide)
  - ✅ Emoji-based status indicators for quick visual assessment
  - ✅ Comprehensive error handling
  - ✅ Docker support for easy deployment

## 📋 Prerequisites

- Python 3.11 or higher
- Cisco Meraki Dashboard API Key
- Network access to Meraki Dashboard API (`api.meraki.com`)

## 🔑 Obtaining Your Meraki API Key

1. Log into the [Meraki Dashboard](https://dashboard.meraki.com)
2. Navigate to **Organization > Settings**
3. Scroll to **Dashboard API access** and enable API access
4. Go to **My Profile** (click your avatar in the top right)
5. Under **API access**, click **Generate new API key**
6. Copy and securely store your API key

⚠️ **Security Note**: Your API key has the same permissions as your user account. Keep it secure and never commit it to version control.

## 🚀 Installation

### Option 1: Docker Deployment (Recommended)

1. **Clone or download the server files:**
```bash
# Create a directory for the server
mkdir meraki-mcp-server
cd meraki-mcp-server
```

2. **Copy all files to the directory:**
   - `meraki_mcp_server.py`
   - `pyproject.toml`
   - `Dockerfile`
   - `docker-compose.yml`
   - `.env.example`

3. **Configure environment variables:**
```bash
cp .env.example .env
# Edit .env and add your Meraki API key
nano .env
```

4. **Build and run with Docker Compose:**
```bash
docker-compose up -d
```

5. **Verify the server is running:**
```bash
docker-compose logs -f meraki-mcp-server
```

### Option 2: Local Python Installation

1. **Install uv package manager:**
```bash
pip install uv
```

2. **Install Python dependencies:**
```bash
uv sync
```

3. **Configure environment variables:**
```bash
cp .env.example .env
# Edit .env and add your Meraki API key
nano .env
```

4. **Run the server:**
```bash
uv run python meraki_mcp_server.py
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MERAKI_API_KEY` | ✅ Yes | - | Your Meraki Dashboard API key |
| `MERAKI_BASE_URL` | No | `https://api.meraki.com/api/v1` | Meraki API base URL |
| `MCP_HOST` | No | `localhost` | Host to bind the MCP server |
| `MCP_PORT` | No | `8000` | Port for the MCP server |

### Regional API Endpoints

For most regions, the default API endpoint works fine. However, for organizations hosted in specific countries, use these base URLs:

| Region | Base URL |
|--------|----------|
| China | `https://api.meraki.cn/api/v1` |
| Europe | `https://api.meraki.com/api/v1` (default) |

See [Meraki API Documentation](https://developer.cisco.com/meraki/api-v1/getting-started/#base-uri) for the complete list.

## 📚 Available Tools

### 1. `get_organizations`
Lists all Meraki organizations accessible with the API key.

**Parameters:** None

**Example Use Cases:**
- Discover available organizations
- First step in exploring Meraki environment
- Verify API key permissions

---

### 2. `get_organization_networks`
Lists all networks within an organization.

**Parameters:**
- `organization_id` (required): Organization ID

**Example Use Cases:**
- View network topology
- Identify networks for monitoring
- Network inventory management

---

### 3. `get_network_devices`
Gets devices in a specific network or organization-wide.

**Parameters:**
- `network_id` (optional): Specific network ID
- `organization_id` (optional): Organization ID for all networks

**Example Use Cases:**
- Device inventory
- Locate specific devices
- Firmware version tracking

**Dual Mode:** ✅ Supports both single network and organization-wide queries

---

### 4. `get_organization_devices`
Gets all devices across an organization.

**Parameters:**
- `organization_id` (required): Organization ID

**Example Use Cases:**
- Complete device inventory
- Organization-wide device management
- Asset tracking

---

### 5. `get_device_statuses`
Retrieves detailed device status with performance metrics.

**Parameters:**
- `organization_id` (required): Organization ID
- `network_ids` (optional): Comma-separated network IDs to filter

**Returns:**
- Online/offline/alerting status
- Performance metrics
- Uplink information
- Client counts
- Component health (power supplies, fans)

**Example Use Cases:**
- Network health monitoring
- Troubleshooting device issues
- Capacity planning
- SLA reporting

---

### 6. `get_network_clients`
Gets clients connected to network(s).

**Parameters:**
- `network_id` (optional): Specific network ID
- `organization_id` (optional): Organization ID for all networks
- `timespan` (optional): Time span in seconds (default: 86400 = 24 hours)

**Example Use Cases:**
- User connectivity monitoring
- Bandwidth analysis
- Client troubleshooting
- Usage tracking

**Dual Mode:** ✅ Supports both single network and organization-wide queries

---

### 7. `get_device_clients`
Gets clients connected to a specific device.

**Parameters:**
- `serial` (required): Device serial number
- `timespan` (optional): Time span in seconds (default: 86400 = 24 hours)

**Example Use Cases:**
- Device-specific troubleshooting
- AP load analysis
- Switch port client tracking

---

### 8. `get_network_ssids`
Gets wireless SSIDs configured in network(s).

**Parameters:**
- `network_id` (optional): Specific network ID
- `organization_id` (optional): Organization ID for all networks

**Returns:**
- SSID configuration
- Authentication modes
- Encryption settings
- Enabled/disabled status

**Example Use Cases:**
- Wireless configuration audit
- SSID management
- Security posture review

**Dual Mode:** ✅ Supports both single network and organization-wide queries

---

### 9. `get_wireless_client_health`
Gets comprehensive wireless client health including RSSI and SNR metrics.

**Parameters:**
- `network_id` (required): Network ID where the client is connected
- `client_id` (required): Client ID (MAC address)
- `organization_id` (required): Organization ID
- `timespan` (optional): Time span in seconds (default: 86400 = 24 hours)

**Returns:**
- Signal quality metrics (RSSI, SNR) correlated by device serial
- Connection attempts and disconnections
- Authentication failures
- Roaming events
- Overall wireless health assessment

**Key Metrics:**
- **RSSI (Signal Strength)**: Average, best, worst values per device
  - Automatically converted to negative dBm values (API returns positive values)
  - Excellent: > -60 dBm
  - Good: -60 to -70 dBm
  - Poor: < -70 dBm
- **SNR (Signal-to-Noise Ratio)**: Average, best, worst values per device
  - Excellent: > 25 dB
  - Good: 15-25 dB
  - Poor: < 15 dB

**Example Use Cases:**
- Wireless troubleshooting and performance analysis
- Signal strength optimization
- Client roaming behavior analysis
- Identifying connectivity issues

---

### 10. `get_network_appliance_firewall_l3_firewall_rules`
Gets Layer 3 (IP-based) firewall rules.

**Parameters:**
- `network_id` (optional): Specific network ID
- `organization_id` (optional): Organization ID for all networks

**Returns:**
- Rule policies (allow/deny)
- Source/destination IP addresses and ports
- Protocols
- Rule comments

**Example Use Cases:**
- Security audit
- Connectivity troubleshooting
- Compliance verification
- Policy documentation

**Dual Mode:** ✅ Supports both single network and organization-wide queries

---

### 11. `get_network_appliance_firewall_l7_firewall_rules`
Gets Layer 7 (application-based) firewall rules.

**Parameters:**
- `network_id` (optional): Specific network ID
- `organization_id` (optional): Organization ID for all networks

**Returns:**
- Application-based rules
- Blocked/allowed applications
- URL filtering rules

**Example Use Cases:**
- Application access control
- Bandwidth management policies
- Content filtering review

**Dual Mode:** ✅ Supports both single network and organization-wide queries

---

### 12. `get_network_appliance_security_events`
Gets security events from MX security appliances.

**Parameters:**
- `network_id` (required): Network ID
- `timespan` (optional): Time span in seconds (default: 86400 = 24 hours)

**Returns:**
- IDS/IPS alerts
- Malware detections
- Security threats
- Event priorities

**Example Use Cases:**
- Security monitoring
- Incident response
- Threat analysis
- Compliance reporting

---

## 🎯 Usage Patterns

### Example 1: Basic Network Health Check

```python
# Using with LibreChat or other MCP clients

# Step 1: List organizations
get_organizations()

# Step 2: Get device statuses for health check
get_device_statuses(organization_id="123456")

# Step 3: Review any security events
get_network_appliance_security_events(network_id="L_123456789")
```

### Example 2: Troubleshooting Wireless Connectivity

```python
# Step 1: Check SSID configuration
get_network_ssids(network_id="L_123456789")

# Step 2: Get comprehensive client health (RSSI, SNR, connectivity events)
get_wireless_client_health(
    network_id="L_123456789",
    client_id="aa:bb:cc:dd:ee:ff",
    organization_id="123456"
)

# Step 3: Check specific device clients
get_device_clients(serial="Q2XX-XXXX-XXXX")
```

### Example 3: Security Audit

```python
# Step 1: Review L3 firewall rules
get_network_appliance_firewall_l3_firewall_rules(organization_id="123456")

# Step 2: Review L7 firewall rules
get_network_appliance_firewall_l7_firewall_rules(organization_id="123456")

# Step 3: Check security events
get_network_appliance_security_events(network_id="L_123456789")
```

### Example 4: Organization-Wide Client Analysis

```python
# Get all clients across all networks
get_network_clients(organization_id="123456", timespan=86400)

# This will automatically:
# 1. Retrieve all networks in the organization
# 2. Query clients for each network
# 3. Aggregate results with network attribution
```

---

## 🔍 API Endpoints Used

| Tool | API Endpoint | Method | Description |
|------|--------------|--------|-------------|
| `get_organizations` | `/organizations` | GET | List organizations |
| `get_organization_networks` | `/organizations/{org_id}/networks` | GET | List networks in org |
| `get_network_devices` | `/networks/{net_id}/devices` | GET | List devices in network |
| `get_organization_devices` | `/organizations/{org_id}/devices` | GET | List devices in org |
| `get_device_statuses` | `/organizations/{org_id}/devices/statuses` | GET | device status & metrics |
| `get_network_clients` | `/networks/{net_id}/clients` | GET | List network clients |
| `get_device_clients` | `/devices/{serial}/clients` | GET | List device clients |
| `get_network_ssids` | `/networks/{net_id}/wireless/ssids` | GET | List wireless SSIDs |
| `get_wireless_client_health` | `/networks/{id}/wireless/clients/{id}/connectivityEvents` | GET | Client connectivity |
| `get_wireless_client_health` | `/organizations/{id}/wireless/devices/signalQuality/byClient` | GET | Signal quality |
| `get_l3_firewall_rules`* | `/networks/{id}/appliance/firewall/l3FirewallRules` | GET | L3 firewall rules |
| `get_l7_firewall_rules`* | `/networks/{id}/appliance/firewall/l7FirewallRules` | GET | L7 firewall rules |
| `get_security_events`* | `/networks/{id}/appliance/security/events` | GET | Security events |

*\* Shortened tool names for table readability*

---

## 🔌 Integration with LibreChat

To use this MCP server with LibreChat:

1. **Add to LibreChat configuration** (`librechat.yaml`):

```yaml
endpoints:
  custom:
    - name: "Cisco Network Assistant"
      apiKey: "your-anthropic-api-key"
      baseURL: "https://api.anthropic.com/v1"
      models:
        default:
          - "claude-sonnet-4-20250514"
      titleConvo: true
      titleModel: "claude-sonnet-4-20250514"
      summarize: false
      summaryModel: "claude-sonnet-4-20250514"
      forcePrompt: false
      modelDisplayLabel: "Claude Sonnet 4"
      addParams:
        tools:
          - type: "mcp_tool"
            mcp:
              server_name: "meraki"
              uri: "http://localhost:8000"
```

2. **Restart LibreChat** to load the new configuration

3. **Start using the assistant** with natural language queries:
   - "What's the health status of our network devices?"
   - "Show me all wireless SSIDs across the organization"
   - "Are there any security events in the last 24 hours?"
   - "Which devices are offline?"

## 🔍 Troubleshooting

### Connection Issues

**Problem:** Cannot connect to Meraki API

**Solutions:**
1. Verify your API key is correct
2. Check network connectivity to `api.meraki.com`
3. Ensure API access is enabled for your organization
4. Verify you're using the correct regional endpoint

### Rate Limiting

**Problem:** Getting rate limit errors

**Solutions:**
- The server implements automatic rate limiting (200ms between requests)
- For large organizations, queries may take longer
- The server automatically retries on 429 errors

### Authentication Errors

**Problem:** 401 Unauthorized errors

**Solutions:**
1. Regenerate your API key in the Meraki Dashboard
2. Ensure the API key has appropriate permissions
3. Verify the API key is correctly set in `.env`

### Docker Issues

**Problem:** Container won't start

**Solutions:**
```bash
# Check logs
docker-compose logs meraki-mcp-server

# Rebuild container
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## 📝 Feature Summary

| Feature | Scope | Output Type |
|---------|-------|-------------|
| **Org Management** | Global | List of organizations |
| **Network Mgmt** | Org | Network inventory & details |
| **Device Inventory** | Org/Network | Device list with details |
| **Device Status** | Org | Online status & health metrics |
| **Client Tracking** | Org/Network | Client list with usage stats |
| **Wireless Health** | Client | Signal quality (RSSI/SNR) & events |
| **SSID Config** | Org/Network | Wireless network settings |
| **L3 Firewall** | Org/Network | IP/Port-based rules |
| **L7 Firewall** | Org/Network | Application-based rules |
| **Security Events** | Network | IDS/IPS alerts & threats |

---

## 📊 Rate Limiting & Performance

- **Automatic Rate Limiting:** 200ms delay between requests
- **Automatic Pagination:** Handles large datasets (1000 items per page)
- **Retry Logic:** Automatically retries on rate limit errors
- **Timeout Handling:** 60-second timeout for API requests

### Performance Tips

1. Use `network_id` filters when possible instead of organization-wide queries
2. Adjust `timespan` parameters to reduce data volume
3. For very large organizations (100+ networks), queries may take several minutes

## 🔒 Security Best Practices

1. **Never commit `.env` file** to version control
2. **Rotate API keys** regularly
3. **Use read-only API keys** when possible
4. **Limit API key scope** to necessary permissions
5. **Monitor API usage** in Meraki Dashboard
6. **Use HTTPS** for MCP server in production
7. **Implement firewall rules** to restrict access to MCP server

## 🐛 Debug Mode

To enable detailed logging:

```bash
# Set Python logging level
export PYTHONLOGLEVEL=DEBUG
python meraki_mcp_server.py
```

Or modify the server code:
```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## 📝 API Documentation

For complete Meraki API documentation, visit:
- [Meraki Dashboard API v1](https://developer.cisco.com/meraki/api-v1/)
- [Getting Started Guide](https://developer.cisco.com/meraki/api-v1/getting-started/)
- [Authorization](https://developer.cisco.com/meraki/api-v1/authorization/)

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:
- Additional API endpoints
- Enhanced error handling
- Performance optimizations
- Additional output formats
- Webhook support
- GraphQL endpoint

## 📄 License

This MCP server is provided as-is for use with Cisco Meraki networks.

## 👤 Author

**Ricardo Kaufmann**

Based on Cisco Meraki Dashboard API v1

## 🙏 Acknowledgments

- Cisco Meraki for their comprehensive API
- FastMCP framework for MCP server implementation
- The Anthropic team for the MCP protocol

## 📞 Support

For issues related to:
- **This MCP Server:** Open an issue in the repository
- **Meraki API:** Contact Meraki Support or visit [Meraki Community](https://community.meraki.com)
- **MCP Protocol:** Visit [Model Context Protocol Documentation](https://modelcontextprotocol.io)

---

**Happy Network Monitoring! 🚀📡**
