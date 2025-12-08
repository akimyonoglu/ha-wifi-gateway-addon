#!/usr/bin/with-contenv bashio

# --- Configuration Variables ---
LAN_INTERFACE=$(bashio::config 'lan_interface')
WAN_INTERFACE=$(bashio::config 'wan_interface')
LAN_ADDRESS=$(bashio::config 'lan_address')
LAN_DHCP_START=$(bashio::config 'lan_dhcp_start')
LAN_DHCP_END=$(bashio::config 'lan_dhcp_end')
LAN_DNS_SERVERS=$(bashio::config 'lan_dns_servers')
SCAN_INTERVAL=$(bashio::config 'scan_interval')
CONNECTION_CHECK_INTERVAL=$(bashio::config 'connection_check_interval')
VERBOSE_LOGGING=$(bashio::config 'verbose_logging')

# Global variable to track current connection
CURRENT_WIFI_SSID=""
CURRENT_WIFI_PRIORITY=999

# --- Wi-Fi Management Functions ---

# Create NetworkManager connection profiles for all configured Wi-Fi networks
create_wifi_profiles() {
    bashio::log.info "Creating NetworkManager profiles for configured Wi-Fi networks..."

    local index=0
    while true; do
        local ssid=$(bashio::config "wifi_networks[${index}].ssid" 2>/dev/null)
        if [[ -z "$ssid" ]]; then
            break
        fi

        local password=$(bashio::config "wifi_networks[${index}].password")
        local priority=$(bashio::config "wifi_networks[${index}].priority")

        # Delete existing connection if it exists
        nmcli con delete "wifi-gateway-${ssid}" 2>/dev/null || true

        # Create new connection profile
        bashio::log.info "Creating profile for SSID: $ssid (Priority: $priority)"
        nmcli con add type wifi \
            con-name "wifi-gateway-${ssid}" \
            ifname "$WAN_INTERFACE" \
            ssid "$ssid" \
            wifi-sec.key-mgmt wpa-psk \
            wifi-sec.psk "$password" \
            autoconnect no \
            connection.autoconnect-priority "$priority"

        ((index++))
    done

    bashio::log.info "Created $index Wi-Fi network profiles"
}

# Scan for available Wi-Fi networks and return list of SSIDs
scan_wifi_networks() {
    if [[ "$VERBOSE_LOGGING" == "true" ]]; then
        bashio::log.debug "Scanning for available Wi-Fi networks..."
    fi

    # Request a fresh scan
    nmcli dev wifi rescan ifname "$WAN_INTERFACE" 2>/dev/null || true
    sleep 2

    # Get list of available SSIDs
    nmcli -t -f SSID dev wifi list ifname "$WAN_INTERFACE" 2>/dev/null | sort -u
}

# Get the best available Wi-Fi network based on priority
# Returns: "SSID:PRIORITY" or empty string if none available
get_best_available_network() {
    local available_ssids=$(scan_wifi_networks)
    local best_ssid=""
    local best_priority=999

    local index=0
    while true; do
        local ssid=$(bashio::config "wifi_networks[${index}].ssid" 2>/dev/null)
        if [[ -z "$ssid" ]]; then
            break
        fi

        local priority=$(bashio::config "wifi_networks[${index}].priority")

        # Check if this SSID is available
        if echo "$available_ssids" | grep -q "^${ssid}$"; then
            if [[ $priority -lt $best_priority ]]; then
                best_ssid="$ssid"
                best_priority=$priority
            fi
        fi

        ((index++))
    done

    if [[ -n "$best_ssid" ]]; then
        echo "${best_ssid}:${best_priority}"
    fi
}

# Connect to a specific Wi-Fi network
connect_to_wifi() {
    local ssid="$1"
    local priority="$2"

    bashio::log.info "Connecting to Wi-Fi network: $ssid (Priority: $priority)"

    # Bring down current connection if any
    if [[ -n "$CURRENT_WIFI_SSID" ]]; then
        nmcli con down "wifi-gateway-${CURRENT_WIFI_SSID}" 2>/dev/null || true
    fi

    # Connect to the new network
    if nmcli con up "wifi-gateway-${ssid}" ifname "$WAN_INTERFACE"; then
        CURRENT_WIFI_SSID="$ssid"
        CURRENT_WIFI_PRIORITY=$priority
        bashio::log.info "Successfully connected to $ssid"

        # Wait for connection to stabilize
        sleep 5
        return 0
    else
        bashio::log.error "Failed to connect to $ssid"
        return 1
    fi
}

# Check if current Wi-Fi connection is healthy
is_wifi_connected() {
    if [[ -z "$CURRENT_WIFI_SSID" ]]; then
        return 1
    fi

    # Check if the connection is active
    local state=$(nmcli -t -f STATE con show "wifi-gateway-${CURRENT_WIFI_SSID}" 2>/dev/null | grep -o "activated")

    if [[ "$state" == "activated" ]]; then
        # Check if we can actually reach the internet (ping gateway or DNS)
        if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

# Monitor and manage Wi-Fi connections
wifi_monitor() {
    local last_scan=0

    while true; do
        local current_time=$(date +%s)

        # Check current connection health
        if ! is_wifi_connected; then
            bashio::log.warning "Wi-Fi connection lost or unhealthy. Attempting reconnection..."
            CURRENT_WIFI_SSID=""
            CURRENT_WIFI_PRIORITY=999

            # Try to connect to best available network
            local best_network=$(get_best_available_network)
            if [[ -n "$best_network" ]]; then
                local ssid="${best_network%:*}"
                local priority="${best_network#*:}"
                connect_to_wifi "$ssid" "$priority"
            else
                bashio::log.error "No configured Wi-Fi networks are available"
            fi
        else
            # Connection is healthy, check if there's a better network available
            if [[ $((current_time - last_scan)) -ge $SCAN_INTERVAL ]]; then
                if [[ "$VERBOSE_LOGGING" == "true" ]]; then
                    bashio::log.debug "Performing periodic Wi-Fi scan..."
                fi

                local best_network=$(get_best_available_network)
                if [[ -n "$best_network" ]]; then
                    local ssid="${best_network%:*}"
                    local priority="${best_network#*:}"

                    # If better network is available (lower priority number), switch to it
                    if [[ $priority -lt $CURRENT_WIFI_PRIORITY ]]; then
                        bashio::log.info "Higher priority network available: $ssid (Priority: $priority vs current: $CURRENT_WIFI_PRIORITY)"
                        connect_to_wifi "$ssid" "$priority"
                    fi
                fi

                last_scan=$current_time
            fi
        fi

        # Sleep before next check
        sleep "$CONNECTION_CHECK_INTERVAL"
    done
}

# --- Robust Cleanup Function ---
# This function uses `while` loops to delete every instance of our rules.
# It runs until `iptables -C` (check) fails, meaning no more matching rules exist.
cleanup() {
    bashio::log.info "--- Running Cleanup Function ---"
    # Clean up NAT MASQUERADE rules
    while iptables-nft -t nat -C POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE >/dev/null 2>&1; do
        if [[ "$VERBOSE_LOGGING" == "true" ]]; then bashio::log.debug "Deleting NAT MASQUERADE rule..."; fi
        iptables-nft -t nat -D POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    done
    
    # Clean up FORWARDING rules
    while iptables-nft -C FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT >/dev/null 2>&1; do
        if [[ "$VERBOSE_LOGGING" == "true" ]]; then bashio::log.debug "Deleting FORWARD rule (LAN -> WAN)..."; fi
        iptables-nft -D FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
    done
    while iptables-nft -C FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; do
        if [[ "$VERBOSE_LOGGING" == "true" ]]; then bashio::log.debug "Deleting FORWARD rule (WAN -> LAN)..."; fi
        iptables-nft -D FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    done
    bashio::log.info "--- Cleanup Complete ---"
}

# --- SIGTERM Handler for graceful shutdown ---
term_handler() {
  bashio::log.warning "Received shutdown signal. Cleaning up..."

  # Stop Wi-Fi monitor
  if [[ -n "$WIFI_MONITOR_PID" ]]; then
    kill "$WIFI_MONITOR_PID" 2>/dev/null || true
  fi

  # Stop dnsmasq
  pkill dnsmasq

  # Clean up iptables rules
  cleanup

  # Disconnect from Wi-Fi
  if [[ -n "$CURRENT_WIFI_SSID" ]]; then
    nmcli con down "wifi-gateway-${CURRENT_WIFI_SSID}" 2>/dev/null || true
  fi

  # Return LAN interface to NetworkManager control
  nmcli dev set "$LAN_INTERFACE" managed yes

  bashio::log.info "Graceful shutdown finished. Exiting."
  exit 0
}
trap 'term_handler' SIGTERM

# --- Main Script ---
bashio::log.info "--- STARTING WI-FI GATEWAY ADD-ON ---"
if [[ "$VERBOSE_LOGGING" == "true" ]]; then bashio::log.info "Verbose logging is ENABLED."; fi

# --- STEP 0: ENSURE CLEAN STATE ---
# Run cleanup first to remove any stale rules from a previous unclean shutdown.
# cleanup

# --- STEP 0.5: Setup Wi-Fi Profiles and Initial Connection ---
bashio::log.info "STEP 0.5: Setting up Wi-Fi network profiles..."
create_wifi_profiles

# Connect to the best available Wi-Fi network
bashio::log.info "Attempting initial Wi-Fi connection..."
best_network=$(get_best_available_network)
if [[ -n "$best_network" ]]; then
    ssid="${best_network%:*}"
    priority="${best_network#*:}"
    if connect_to_wifi "$ssid" "$priority"; then
        bashio::log.info "Initial Wi-Fi connection established to $ssid"
    else
        bashio::log.error "Failed to establish initial Wi-Fi connection. Gateway may not function properly."
    fi
else
    bashio::log.error "No configured Wi-Fi networks are available. Cannot start gateway."
    exit 1
fi

# Start Wi-Fi monitoring in the background
bashio::log.info "Starting Wi-Fi monitor..."
wifi_monitor &
WIFI_MONITOR_PID=$!

# --- STEP 1: Claim the LAN interface ---
bashio::log.info "STEP 1: Setting $LAN_INTERFACE to unmanaged by host..."
nmcli dev set "$LAN_INTERFACE" managed no

# --- STEP 2: Configure the LAN interface ---
bashio::log.info "STEP 2: Configuring IP address for $LAN_INTERFACE..."
ip link set "$LAN_INTERFACE" down && sleep 1
ip addr flush dev "$LAN_INTERFACE" && sleep 1
ip addr add "${LAN_ADDRESS}/24" dev "$LAN_INTERFACE" && sleep 1
ip link set "$LAN_INTERFACE" up && sleep 3

# --- STEP 2 VERIFICATION ---
if [[ "$VERBOSE_LOGGING" == "true" ]]; then
    bashio::log.info "--- [DEBUG] VERIFICATION: 'ip addr show $LAN_INTERFACE' ---"
    ip addr show "$LAN_INTERFACE" || bashio::log.warning "Could not get status for $LAN_INTERFACE"
    bashio::log.info "----------------------------------------------------"
fi

# --- STEP 3: Configure Firewall ---
bashio::log.info "STEP 3: Configuring Firewall Policy and Rules..."
iptables-nft -P FORWARD ACCEPT
iptables-nft -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
iptables-nft -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables-nft -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

# --- STEP 3 VERIFICATION ---
if [[ "$VERBOSE_LOGGING" == "true" ]]; then
    bashio::log.info "--- [DEBUG] VERIFICATION: FIREWALL RULES ---"
    bashio::log.info "--- [DEBUG] NAT Table POSTROUTING Chain ---"
    iptables-nft -t nat -L POSTROUTING -n -v || bashio::log.warning "Could not list NAT table."
    bashio::log.info "--- [DEBUG] Filter Table FORWARD Chain ---"
    iptables-nft -L FORWARD -n -v || bashio::log.warning "Could not list Filter table."
    bashio::log.info "------------------------------------------"
fi

# --- STEP 4: Launch DHCP server ---
bashio::log.info "STEP 4: Starting DHCP server on $LAN_INTERFACE..."
DNS_OPTIONS=""
for DNS_SERVER in $LAN_DNS_SERVERS; do DNS_OPTIONS="${DNS_OPTIONS} --dhcp-option=option:dns-server,${DNS_SERVER}"; done
DNSMASQ_LOG_FLAGS=""
if [[ "$VERBOSE_LOGGING" == "true" ]]; then DNSMASQ_LOG_FLAGS="--log-queries --log-dhcp"; fi

dnsmasq --interface="$LAN_INTERFACE" --dhcp-range="$LAN_DHCP_START","$LAN_DHCP_END",12h --dhcp-option=option:router,"$LAN_ADDRESS" $DNS_OPTIONS $DNSMASQ_LOG_FLAGS --no-daemon

bashio::log.error "FATAL: DHCP server has stopped."