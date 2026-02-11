# Cisco Catalyst SD-WAN MCP Server

## 📋 Overview

The Cisco Catalyst SD-WAN MCP Server provides **16 tools** for comprehensive monitoring and management capabilities for your SD-WAN fabric.

## 🛠️ Available Tools

### 1. **get_device_health** 
Monitor device health metrics including CPU, memory, disk usage, and uptime.

**Capabilities:**
- ✅ Single device health check (provide device_id)
- ✅ All devices health overview (no device_id)
- Displays: CPU load, memory usage, disk space, uptime, reachability

**Example Usage:**
```python
# Get health for specific device
result = await get_device_health(device_id="10.1.1.1")

# Get health for all devices
result = await get_device_health()
```

**Output Includes:**
- 🟢 Healthy devices (CPU < 60%, Memory < 75%)
- 🟡 Warning devices (CPU 60-80%, Memory 75-90%)
- 🔴 Critical devices (CPU > 80%, Memory > 90%)

---

### 2. **get_control_connections**
Monitor control plane connections between edge devices and controllers.

**Capabilities:**
- ✅ Single device control connections (provide device_id)
- ✅ All devices control connections overview (no device_id)
- Shows: vSmart, vBond, vManage connections, protocol, state, uptime

**Example Usage:**
```python
# Get control connections for specific device
result = await get_control_connections(device_id="10.1.1.1")

# Get control connections for all devices
result = await get_control_connections()
```

**Output Includes:**
- Connection state (🟢 UP / 🔴 DOWN)
- Peer type and IP address
- Protocol used
- Uptime information
- Alerts for devices with connection issues

---

### 3. **get_bfd_sessions**
Monitor BFD (Bidirectional Forwarding Detection) sessions for tunnel health.

**Capabilities:**
- ✅ Single device BFD sessions (provide device_id)
- ✅ All devices BFD sessions overview (no device_id)
- Shows: Session state, source/destination, color, transitions, uptime

**Example Usage:**
```python
# Get BFD sessions for specific device
result = await get_bfd_sessions(device_id="10.1.1.1")

# Get BFD sessions for all devices
result = await get_bfd_sessions()
```

**Output Includes:**
- Session state (🟢 UP / 🔴 DOWN)
- Source and destination IP addresses
- Transport colors (MPLS, Internet, etc.)
- Transition count
- Global summary of all BFD sessions

---

### 4. **get_interfaces**
Get detailed interface information, IP addresses, and statistics.

**Capabilities:**
- ✅ Single device interfaces (provide device_id)
- ✅ All devices interfaces overview (no device_id)
- Shows: Status, IP addresses, MAC, bandwidth, MTU, RX/TX statistics

**Example Usage:**
```python
# Get interfaces for specific device
result = await get_interfaces(device_id="10.1.1.1")

# Get interfaces for all devices
result = await get_interfaces()
```

**Output Includes:**
- Interface name and operational status
- IP address and subnet mask
- MAC address
- Speed and MTU
- 📥 RX packets, bytes, errors
- 📤 TX packets, bytes, errors

---

### 5. **get_bgp_monitoring**
Real-time BGP monitoring including neighbors and routing information.

**Capabilities:**
- ✅ Single device BGP info (provide device_id)
- ✅ All devices BGP overview (no device_id)
- Shows: BGP neighbors, session state, AS numbers, prefix counts

**Example Usage:**
```python
# Get BGP monitoring for specific device
result = await get_bgp_monitoring(device_id="10.1.1.1")

# Get BGP monitoring for all devices
result = await get_bgp_monitoring()
```

**Output Includes:**
- Router ID and local AS number
- BGP neighbor IP and AS number
- Session state (🟢 Established / 🔴 Other)
- Prefixes received and installed
- Uptime information

---

### 6. **get_omp_monitoring**
Real-time OMP (Overlay Management Protocol) monitoring.

**Capabilities:**
- ✅ Single device OMP info (provide device_id)
- ✅ All devices OMP overview (no device_id)
- Shows: OMP peers, session state, routes, TLOCs advertised/received

**Example Usage:**
```python
# Get OMP monitoring for specific device
result = await get_omp_monitoring(device_id="10.1.1.1")

# Get OMP monitoring for all devices
result = await get_omp_monitoring()
```

**Output Includes:**
- OMP peer IP and type (vSmart/vEdge)
- Session state (🟢 UP / 🔴 DOWN)
- Routes received/installed/sent
- TLOCs received/installed/sent
- Uptime and state information

---

### 7. **get_configuration_groups**
List all configuration groups and their associated devices.

**Capabilities:**
- ✅ Lists all configuration groups
- ✅ Shows devices associated with each group
- Displays: Group name, description, solution type, device count

**Example Usage:**
```python
# Get all configuration groups with device associations
result = await get_configuration_groups()
```

**Output Includes:**
- Configuration group name and ID
- Group description
- Solution type (SD-WAN, SD-Routing, etc.)
- Number of associated devices
- List of devices in each group
- Device deployment status

---

### 8. **get_application_health**
Get application health statistics for a specific site.

**Capabilities:**
- ✅ Detailed application metrics (latency, loss, jitter)
- ✅ QoE (Quality of Experience) scores
- ✅ Categorization (Good/Fair/Poor)
- Shows: Application name, family, health status

**Example Usage:**
```python
# Get application health for a specific site
result = await get_application_health(site_id="100")
```

**Output Includes:**
- 🟢 Good applications cost
- 🟡 Fair applications count
- 🔴 Poor applications count
- Detailed list of applications with metrics

---

### 9. **start_nwpi_trace**
Start a Network Wide Path Insight (NWPI) trace for troubleshooting.

**Capabilities:**
- ✅ Traces flows for a specific site
- ✅ Auto-trace for 1 minute
- ✅ Captures drops, blocks, and routing issues

**Example Usage:**
```python
# Start NWPI trace for a site
result = await start_nwpi_trace(site_id="100")
# Note: Returns trace_id and entry_time for analysis
```

**Output Includes:**
- Trace ID and Entry Time
- Participating devices
- Instructions for analysis

---

### 10. **analyze_nwpi_trace**
Analyze the results of a completed NWPI trace.

**Capabilities:**
- ✅ Detailed hop-by-hop analysis
- ✅ Identifies specific drop/block reasons
- ✅ Firewall and policy inspection results

**Example Usage:**
```python
# Analyze a completed trace
result = await analyze_nwpi_trace(
    trace_id="12345", 
    entry_time="1234567890"
)
```

**Output Includes:**
- Drop/Block reasons (ACL, Firewall, Routing)
- Impacted applications
- Flow details

---

### 11. **get_qos_configuration**
View QoS policer configuration for a device.

**Capabilities:**
- ✅ Finds associated policy group
- ✅ Retrieves application-priority profile
- ✅ Shows current policer settings (Rate, Burst, Exceed)

**Example Usage:**
```python
# Get QoS config for a device
result = await get_qos_configuration(device_id="10.1.1.1")
```

**Output Includes:**
- Policy group and profile names
- Policer rate (Kbps) and burst (bytes)
- Configuration IDs

---

### 12. **update_qos_policer**
Update QoS policer rate and burst settings.

**Capabilities:**
- ✅ Modifies rate and burst values
- ✅ Preserves other settings
- ✅ Auto-redeploys policy to device

**Example Usage:**
```python
# Update policer to 10Mbps rate, 15000 bytes burst
result = await update_qos_policer(
    device_id="10.1.1.1",
    rate_kbps=10000,
    burst_bytes=15000
)
```

**Output Includes:**
- Confirmation of changes
- Previous vs New values
- Deployment status

---

### 13. **deploy_policy_group**
Deploy a policy group to a list of devices.

**Capabilities:**
- ✅ Deploys policy group by name
- ✅ Handles multiple devices
- ✅ Auto-resolves device UUIDs

**Example Usage:**
```python
# Deploy policy group to devices
result = await deploy_policy_group(
    policy_group_name="Default_Policy",
    device_ids="10.1.1.1, 10.1.1.2"
)
```

**Output Includes:**
- Deployment status
- Task ID for monitoring

---

### 14. **get_software_versions**
Unchanged - Analyzes software versions across the SD-WAN fabric.

### 15. **get_device_details**
Unchanged - Provides comprehensive device inventory.

### 16. **get_version_compliance**
Unchanged - Checks version compliance against target version.

---

## 🔧 Tool Parameters

All tools support:

**Required Parameters:**
- None for overview mode (all devices)
- `device_id` for specific device mode

**Optional Parameters:**
- `vmanage_url`: Custom vManage URL (overrides default)

---

## 🎯 Usage Patterns

### Pattern 1: Quick Overview
Get a summary of all devices:
```python
await get_device_health()
await get_control_connections()
await get_bfd_sessions()
await get_interfaces()
```

### Pattern 2: Deep Dive on Specific Device
Detailed analysis of one device:
```python
device = "10.1.1.1"
await get_device_health(device_id=device)
await get_control_connections(device_id=device)
await get_bfd_sessions(device_id=device)
await get_interfaces(device_id=device)
await get_bgp_monitoring(device_id=device)
await get_omp_monitoring(device_id=device)
```

### Pattern 3: Protocol Monitoring
Monitor routing protocols:
```python
await get_bgp_monitoring()
await get_omp_monitoring()
```

### Pattern 4: Configuration Management
Check configuration groups:
```python
await get_configuration_groups()
```

### Pattern 5: Application & Network Visibility
Troubleshoot application issues:
```python
# Check app health
await get_application_health(site_id="100")

# Run deep-dive trace
trace = await start_nwpi_trace(site_id="100")
# Wait 70 seconds...
await analyze_nwpi_trace(trace_id=trace.id, entry_time=trace.time)
```

### Pattern 6: QoS Management
Adjust bandwidth limits:
```python
# Check current settings
await get_qos_configuration(device_id="10.1.1.1")

# Update limits
await update_qos_policer(
    device_id="10.1.1.1", 
    rate_kbps=20000, 
    burst_bytes=30000
)
```

---

## 📈 Output Format

All tools provide **human-readable text with emojis** for easy visualization:

- 🟢 = Healthy/UP/Normal
- 🟡 = Warning
- 🔴 = Critical/DOWN/Error
- ⚠️ = Issue detected
- ❌ = Error occurred
- ✅ = Success
- 📊 = Statistics
- 🔧 = Controllers
- 🌐 = Routers
- 🖥️ = Device
- 🔗 = Connection
- 🤝 = Peer/Neighbor

---

## 🔍 API Endpoints Used

| Tool | API Endpoint |
|------|-------------|
| get_device_health | `/dataservice/device/system/status` |
| get_control_connections | `/dataservice/device/control/connections` |
| get_bfd_sessions | `/dataservice/device/bfd/sessions` |
| get_interfaces | `/dataservice/device/interface` |
| get_bgp_monitoring | `/dataservice/device/bgp/neighbors`<br>`/dataservice/device/bgp/summary` |
| get_omp_monitoring | `/dataservice/device/omp/peers`<br>`/dataservice/device/omp/summary` |
| get_configuration_groups | `/dataservice/v1/config-group` |
| get_application_health | `/dataservice/statistics/perfmon/applications/site/health` |
| start_nwpi_trace | `/dataservice/stream/device/nwpi/trace/start` |
| analyze_nwpi_trace | `/dataservice/stream/device/nwpi/exportTrace` |
| get_qos_configuration | `/dataservice/v1/feature-profile/sdwan/policy-object` |
| update_qos_policer | `/dataservice/v1/feature-profile/sdwan/policy-object/.../policer` |
| deploy_policy_group | `/dataservice/v1/policy-group/device/associate` |

---

## 💡 Best Practices

### 1. Performance Considerations
- When querying all devices, the server makes multiple API calls
- For large fabrics (100+ devices), queries may take 30-60 seconds
- Use specific device_id when possible for faster responses

### 2. Error Handling
- All tools handle API errors gracefully
- If a device doesn't support a feature (e.g., BGP), it's noted in output
- Network connectivity issues are reported clearly

### 3. Monitoring Strategy
**Real-time Monitoring:**
- Run `get_device_health()` every 5 minutes
- Run `get_control_connections()` every 10 minutes
- Run `get_bfd_sessions()` every 5 minutes

**Periodic Checks:**
- Run `get_bgp_monitoring()` every 15 minutes
- Run `get_omp_monitoring()` every 15 minutes
- Run `get_interfaces()` every 30 minutes

**Configuration Management:**
- Run `get_configuration_groups()` on-demand or daily

---

## 🚀 Deployment

### Same Docker Setup
The server uses the standard Docker setup:

```bash
# Build
docker compose build --no-cache

# Start
docker compose up -d

# View logs
docker compose logs -f
```

### Same Environment Variables
No new environment variables needed. Uses existing:
- `VMANAGE_USERNAME`
- `VMANAGE_PASSWORD`
- `VMANAGE_HOST`
- `VMANAGE_PORT`
- `VMANAGE_VERIFY_SSL`
- `MCP_HOST`
- `MCP_PORT`

---

## 📝 Feature Summary

| Feature | Devices Supported | Output Type |
|---------|-------------------|-------------|
| **Device Health** | Single / All | Health metrics with color coding |
| **Control Connections** | Single / All | Connection state and uptime |
| **BFD Sessions** | Single / All | Tunnel health and statistics |
| **Interfaces** | Single / All | Interface status and traffic stats |
| **BGP Monitoring** | Single / All | BGP neighbors and session state |
| **OMP Monitoring** | Single / All | OMP peers and route information |
| **Configuration Groups** | All | Groups with device associations |
| **App Health** | Site | QoE scores and metrics |
| **NWPI Trace** | Site | Deep packet inspection/trace |
| **QoS Config** | Single | Policer rate and burst settings |
| **Policy Deploy** | Multiple | Deployment status |
| **Software Versions** | All | Version analysis |
| **Device Details** | All | Inventory details |
| **Version Compliance** | All | Compliance check |

---

## 🎓 Use Cases

### Network Operations
- **Daily Health Check**: Run all health tools to verify network status
- **Troubleshooting**: Deep dive into specific device with all tools
- **Capacity Planning**: Monitor interface statistics and CPU/memory

### Change Management
- **Pre-Change Validation**: Check all connections and sessions before changes
- **Post-Change Verification**: Verify everything came back up correctly
- **Configuration Audit**: Review configuration groups and associations

### Proactive Monitoring
- **Identify Issues Early**: Detect down sessions before users report problems
- **Trend Analysis**: Monitor CPU/memory over time
- **Compliance Checking**: Ensure BGP/OMP peers are as expected

---

## 🔗 Documentation References

- [Cisco SD-WAN API Documentation](https://developer.cisco.com/docs/sdwan/)
- [Device Realtime Monitoring API](https://developer.cisco.com/docs/sdwan/device-realtime-monitoring/)
- [Configuration Groups Guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/config-groups/configuration-group-guide/)

---

## 📞 Support

For issues or questions:
- Check server logs: `docker compose logs -f`
- Verify vManage connectivity and credentials
- Ensure vManage REST API is enabled
- Confirm user has appropriate API permissions

---

**Version**: 2.0
**Author**: Ricardo Kaufmann
**Last Updated**: November 2025
