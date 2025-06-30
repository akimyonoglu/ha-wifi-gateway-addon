# /addons/ha-wifi-gateway-addon/Dockerfile
ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install all necessary packages to be self-sufficient.
RUN apk add --no-cache dnsmasq iptables iproute2 networkmanager-cli

# Copy the run script into the container
COPY run.sh /

# Make the run script executable
RUN chmod a+x /run.sh

# Set the command to run when the container starts
CMD [ "/run.sh" ]