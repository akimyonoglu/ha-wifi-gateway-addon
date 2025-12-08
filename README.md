# ha-wifi-gateway-addon
Home Assistant AddOn: Shares the Pi's Wi-Fi connection out to the Ethernet port using NAT (atcs like Wi-Fi Client). This is a system-level service that directly configures host networking.

Forked from `https://github.com/eximius313/ha-wifi-gateway-addon` to add following features:
- Multi wifi support with priority setting and automatic switching
- Network isolation with policy-based routing
- Pinned network mode for simple single-network operation

## Features

- **Multi-Network Mode**: Automatic failover between multiple Wi-Fi networks with priority-based selection
- **Pinned Network Mode**: Lock to a single Wi-Fi network with no health checks or failover (prevents false reconnections)
- **Network Isolation**: Complete routing isolation between gateway traffic and Home Assistant host network
- **NAT Gateway**: Shares Wi-Fi connection with Ethernet clients
- **DHCP Server**: Automatic IP assignment for LAN clients

## Configuration Options

### Basic Settings
- `lan_interface`: Ethernet interface for LAN clients (default: "end0")
- `wan_interface`: Wi-Fi interface for WAN connection (default: "wlan0")
- `lan_address`: Gateway IP address (default: "192.168.5.1")
- `lan_dhcp_start` / `lan_dhcp_end`: DHCP IP range
- `lan_dns_servers`: DNS servers for LAN clients

### Wi-Fi Settings
- `wifi_networks`: List of Wi-Fi networks with `ssid`, `password`, and `priority` (1-100, lower = higher priority)
- `pin_wifi_network`: **(Optional)** SSID to pin - disables failover and health checks, only uses this network

### Advanced Settings
- `scan_interval`: How often to scan for better networks (default: 60 seconds)
- `connection_check_interval`: How often to check connection health (default: 10 seconds)
- `verbose_logging`: Enable debug logging

## Usage Modes

### Multi-Network Mode (Default)
Leave `pin_wifi_network` empty for automatic multi-network management:
- Connects to highest priority available network
- Automatically fails over to backup networks
- Periodically scans for better networks and upgrades

### Pinned Network Mode
Set `pin_wifi_network` to a specific SSID (e.g., "MyHomeWiFi") for simple operation:
- Only connects to the specified network
- Uses NetworkManager's built-in autoconnect (no custom monitoring)
- No health checks or periodic polling
- NetworkManager automatically reconnects if connection is lost
- Zero monitoring overhead
- **Recommended** for stable single-network environments

**Example Configuration:**
```yaml
pin_wifi_network: "MyHomeWiFi"
wifi_networks:
  - ssid: "MyHomeWiFi"
    password: "mypassword123"
    priority: 1
```

## Installation
1. Go to the **Add-on store**, click **⋮ → Repositories**, fill in</br> `https://github.com/akimyonoglu/ha-wifi-gateway-addon` and click **Add → Close** or click the **Add repository** button below, click **Add → Close** (You might need to enter the **internal IP address** of your Home Assistant instance first).  
   [![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fakimyonoglu%2Fha-wifi-gateway-addon)
