#!/usr/bin/with-contenv bashio

# --- Configuration Variables ---
LAN_INTERFACE=$(bashio::config 'lan_interface')
WAN_INTERFACE=$(bashio::config 'wan_interface')
LAN_ADDRESS=$(bashio::config 'lan_address')
LAN_DHCP_START=$(bashio::config 'lan_dhcp_start')
LAN_DHCP_END=$(bashio::config 'lan_dhcp_end')
LAN_DNS_SERVERS=$(bashio::config 'lan_dns_servers')
VERBOSE_LOGGING=$(bashio::config 'verbose_logging')

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
  pkill dnsmasq
  cleanup
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