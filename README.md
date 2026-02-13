# BRKENT-2215
# 🌐 Network MCP Suite

A suite of **Model Context Protocol (MCP) servers** designed to bridge AI assistants with network infrastructure platforms.

---

## 📖 Overview

The Network MCP Suite provides a standardized way for MCP-compliant AI clients (like Cursor, Claude Desktop, etc.) to interact with network management systems. Each server runs as a standalone service, exposing specific capabilities of the underlying platform.

```
┌─────────────────┐    ┌──────────────────────────────────┐
│                 │    │          Docker Host             │
│   MCP Client    │    │                                  │
│                 │    │  ┌─────────────────────────────┐ │
│ • Cursor IDE    │────┼─▶│ Meraki MCP        :8000     │ │
│ • LibreChat     │    │  ├─────────────────────────────┤ │
│ • Claude Desktop│────┼─▶│ NetBox MCP        :8001     │ │
│ • Other MCP     │    │  ├─────────────────────────────┤ │
│   Clients       │────┼─▶│ Catalyst SD-WAN   :8007     │ │
│                 │    │  └─────────────────────────────┘ │
└─────────────────┘    └──────────────────────────────────┘
```

> ✅ Simple setup — no authentication required  
> ✅ Individual server access and configuration  
> ✅ Flexible port-based deployment  
> ✅ Perfect for development and testing  

---

## 🧩 MCP Servers

### 1. 🟢 Meraki MCP Server

| | |
|---|---|
| **Directory** | `meraki-mcp-server` |
| **Port** | `8000` |

The Meraki MCP server enables interaction with the **Cisco Meraki Dashboard API**. It allows AI agents to retrieve organization details, network statuses, device information, and client data — essential for cloud-managed network operations and troubleshooting.

---

### 2. 📦 NetBox MCP Server

| | |
|---|---|
| **Directory** | `netbox-mcp-server` |
| **Port** | `8001` |

The NetBox MCP server interfaces with **NetBox**, the leading open-source DCIM (Data Center Infrastructure Management) and IPAM (IP Address Management) tool. It provides capabilities to query devices, IP addresses, prefixes, and other infrastructure source-of-truth data.

---

### 3. 🔷 Catalyst SD-WAN MCP Server

| | |
|---|---|
| **Directory** | `catalyst-sdwan-mcp-server` |
| **Port** | `8007` |

The Catalyst SD-WAN MCP server connects to **Cisco Catalyst SD-WAN. It exposes operational data and configuration capabilities for SD-WAN overlays, allowing agents to inspect control connections, device status, and policy configurations.

---

## 🔧 LibreChat Configuration

To use these MCP servers with LibreChat, add the following to your `librechat.yaml`:

```yaml
mcpServers:
  Meraki-MCP-Server:
    type: streamable-http
    url: http://meraki-mcp-server:8000/sse
    timeout: 60000
  Netbox-MCP-Server:
    type: streamable-http
    url: http://netbox-mcp-server:8001/sse
    timeout: 60000
  Catalyst-SDWAN-MCP-Server:
    type: streamable-http
    url: http://catalyst-sdwan-mcp-server:8007/sse
    timeout: 60000
```

---

## ⚠️ Disclaimer

> This project is part of the **Cisco DevNet** community and is provided as example code for demonstration and learning purposes. It is **not officially supported by Cisco Systems** and is not intended for production use without proper testing and customization for your specific environment.
