# 🚀 Quick Start Guide - Cisco Meraki MCP Server

## Get Started in 5 Minutes!

### Step 1: Get Your Meraki API Key
1. Login to [Meraki Dashboard](https://dashboard.meraki.com)
2. Click your avatar → **My Profile**
3. Scroll to **API access** → **Generate new API key**
4. Copy and save your API key securely

### Step 2: Setup with Docker (Easiest)

```bash
# 1. Create configuration file
cp .env.example .env

# 2. Edit .env and add your API key
nano .env
# or use your preferred editor

# 3. Start the server
docker-compose up -d

# 4. Check logs to confirm it's running
docker-compose logs -f meraki-mcp-server
```

You should see:
```
✅ Successfully connected to Meraki Dashboard API
📊 Found X organization(s)
🌐 MCP Server starting on localhost:8000
```

### Step 3: Configure LibreChat

Add to your `librechat.yaml`:

```yaml
endpoints:
  custom:
    - name: "Cisco Network Assistant"
      apiKey: "your-anthropic-api-key"
      baseURL: "https://api.anthropic.com/v1"
      models:
        default:
          - "claude-sonnet-4-20250514"
      addParams:
        tools:
          - type: "mcp_tool"
            mcp:
              server_name: "meraki"
              uri: "http://localhost:8000"
```

### Step 4: Start Using!

Try these commands in LibreChat:
- "List all our Meraki organizations"
- "Show me the health status of all network devices"
- "What security events occurred in the last 24 hours?"
- "Show me all wireless SSIDs across the organization"

## Alternative: Local Python Setup

If you prefer not to use Docker:

```bash
# 1. Install uv package manager
pip install uv

# 2. Install dependencies
uv sync

# 3. Setup environment
cp .env.example .env
nano .env  # Add your API key

# 4. Run the server
uv run python meraki_mcp_server.py
```

## Troubleshooting

### ❌ "MERAKI_API_KEY environment variable is required"
→ Make sure you created `.env` file and added your API key

### ❌ "Failed to connect to Meraki API"
→ Check your API key is valid and has correct permissions

### ❌ Docker container won't start
→ Run: `docker-compose logs meraki-mcp-server` to see error details

## Need More Help?

See the full [README.md](README.md) for:
- Complete list of available tools
- Detailed usage examples
- Advanced configuration options
- Security best practices

---

**Questions?** Check the README or Meraki API documentation.

**Ready to explore!** 🎉
