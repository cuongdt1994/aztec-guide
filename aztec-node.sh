#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    error "Please do not run this script as root. Run as a regular user with sudo privileges."
fi

USER=$(whoami)
AZTEC_DIR="/home/$USER/.aztec"

log "Starting Aztec Validator Node Setup"

# Step 1: System checks and Docker installation
log "Step 1: System checks and Docker installation"

# Check if Docker is already installed
if command -v docker &> /dev/null; then
    log "Docker is already installed. Version: $(docker --version)"
else
    log "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    log "Added $USER to docker group. You may need to log out and back in for this to take effect."
fi

# Verify Docker is running
if ! sudo systemctl is-active --quiet docker; then
    log "Starting Docker service..."
    sudo systemctl start docker
    sudo systemctl enable docker
fi

# Step 2: Setup aztec directory and download bin
log "Step 2: Setting up Aztec directory and downloading binaries"

# Create directory with proper permissions
mkdir -p "$AZTEC_DIR"
chmod 755 "$AZTEC_DIR"

# Backup existing installation if it exists
if [ -f "$AZTEC_DIR/bin/aztec" ]; then
    log "Backing up existing Aztec installation..."
    mv "$AZTEC_DIR/bin" "$AZTEC_DIR/bin.backup.$(date +%Y%m%d_%H%M%S)"
fi

log "Downloading Aztec binaries..."
if ! curl -sL --fail https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/bin.tar.gz -o "$AZTEC_DIR/bin.tar.gz"; then
    error "Failed to download Aztec binaries. Please check your internet connection and try again."
fi

# Verify download
if [ ! -f "$AZTEC_DIR/bin.tar.gz" ]; then
    error "Download failed - binary archive not found"
fi

log "Extracting binaries..."
tar -xzf "$AZTEC_DIR/bin.tar.gz" -C "$AZTEC_DIR"
rm "$AZTEC_DIR/bin.tar.gz"

# Set executable permissions
chmod +x "$AZTEC_DIR/bin/aztec"

# Verify binary works
if ! "$AZTEC_DIR/bin/aztec" --help &> /dev/null; then
    warn "Aztec binary may not be working properly. Please verify manually."
fi

# Step 3: Create .env file with user input
log "Step 3: Configuration setup"

# Get public IP with fallback
log "Detecting public IP address..."
P2P_IP=$(curl -s --connect-timeout 10 https://api.ipify.org || curl -s --connect-timeout 10 http://ipv4.icanhazip.com || echo "")

if [ -z "$P2P_IP" ]; then
    warn "Could not auto-detect public IP. Please enter it manually."
    read -p "Enter your public IP address: " P2P_IP
else
    log "Detected public IP: $P2P_IP"
    read -p "Is this IP correct? (y/n): " confirm_ip
    if [[ $confirm_ip != "y" && $confirm_ip != "Y" ]]; then
        read -p "Enter your correct public IP address: " P2P_IP
    fi
fi

# Validate IP format (basic check)
if [[ ! $P2P_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error "Invalid IP address format: $P2P_IP"
fi

echo
log "Please provide the following configuration parameters:"
echo

# Get Ethereum hosts
while true; do
    read -p "Enter ETHEREUM_HOSTS (comma separated URLs): " ETHEREUM_HOSTS
    if [ -n "$ETHEREUM_HOSTS" ]; then
        break
    fi
    warn "ETHEREUM_HOSTS cannot be empty. Please enter at least one URL."
done

# Get L1 consensus hosts
while true; do
    read -p "Enter L1_CONSENSUS_HOST_URLS (comma separated URLs): " L1_CONSENSUS_HOST_URLS
    if [ -n "$L1_CONSENSUS_HOST_URLS" ]; then
        break
    fi
    warn "L1_CONSENSUS_HOST_URLS cannot be empty. Please enter at least one URL."
done

# Get validator private key (with hidden input)
while true; do
    read -s -p "Enter VALIDATOR_PRIVATE_KEY (input hidden): " VALIDATOR_PRIVATE_KEY
    echo
    if [ -n "$VALIDATOR_PRIVATE_KEY" ]; then
        break
    fi
    warn "VALIDATOR_PRIVATE_KEY cannot be empty."
done

# Get validator address
while true; do
    read -p "Enter VALIDATOR address (coinbase): " COINBASE
    if [ -n "$COINBASE" ]; then
        break
    fi
    warn "VALIDATOR address cannot be empty."
done

# Create .env file with proper permissions
log "Creating configuration file..."
cat > "$AZTEC_DIR/.env" <<EOF
HOME=/home/$USER
ETHEREUM_HOSTS=$ETHEREUM_HOSTS
L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS
VALIDATOR_PRIVATE_KEY=$VALIDATOR_PRIVATE_KEY
COINBASE=$COINBASE
P2P_IP=$P2P_IP
EOF

# Secure the .env file (contains private key)
chmod 600 "$AZTEC_DIR/.env"
log "Configuration file created at $AZTEC_DIR/.env with secure permissions"

# Display config (without private key)
log "Configuration summary:"
echo "HOME=/home/$USER"
echo "ETHEREUM_HOSTS=$ETHEREUM_HOSTS"
echo "L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS"
echo "VALIDATOR_PRIVATE_KEY=***HIDDEN***"
echo "COINBASE=$COINBASE"
echo "P2P_IP=$P2P_IP"

# Step 4: Create systemd service
log "Step 4: Creating systemd service"

# Backup existing service if it exists
if [ -f "/etc/systemd/system/aztec.service" ]; then
    log "Backing up existing service file..."
    sudo cp /etc/systemd/system/aztec.service /etc/systemd/system/aztec.service.backup.$(date +%Y%m%d_%H%M%S)
fi

sudo tee /etc/systemd/system/aztec.service > /dev/null <<EOF
[Unit]
Description=Aztec Validator Node
Documentation=https://docs.aztec.network/
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$AZTEC_DIR
EnvironmentFile=$AZTEC_DIR/.env
ExecStart=$AZTEC_DIR/bin/aztec start --node --archiver --sequencer \\
  --network alpha-testnet \\
  --l1-rpc-urls \${ETHEREUM_HOSTS} \\
  --l1-consensus-host-urls \${L1_CONSENSUS_HOST_URLS} \\
  --sequencer.validatorPrivateKey \${VALIDATOR_PRIVATE_KEY} \\
  --sequencer.coinbase \${COINBASE} \\
  --p2p.p2pIp \${P2P_IP} \\
  --p2p.p2pPort 40401 \\
  --port 8081

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=0

# Resource limits (adjust as needed)
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aztec

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$AZTEC_DIR

[Install]
WantedBy=multi-user.target
EOF

log "Systemd service file created"

# Reload systemd and enable service
log "Configuring systemd service..."
sudo systemctl daemon-reload
sudo systemctl enable aztec.service

# Step 5: Final checks and service start
log "Step 5: Starting Aztec service"

# Check if service is already running
if sudo systemctl is-active --quiet aztec.service; then
    log "Stopping existing Aztec service..."
    sudo systemctl stop aztec.service
fi

# Start the service
log "Starting Aztec validator service..."
if sudo systemctl start aztec.service; then
    log "Aztec service started successfully!"
else
    error "Failed to start Aztec service. Check logs with: sudo journalctl -u aztec.service -f"
fi

# Wait a moment and check status
sleep 3
if sudo systemctl is-active --quiet aztec.service; then
    log "Service is running properly"
else
    warn "Service may have issues. Check status with: sudo systemctl status aztec.service"
fi

# Final instructions
echo
log "=== SETUP COMPLETE ==="
echo
echo -e "${BLUE}IMPORTANT FIREWALL CONFIGURATION:${NC}"
echo "Please ensure the following TCP ports are open:"
echo "  • TCP 8081 (Aztec node main communication)"
echo "  • TCP 40401 (P2P network port)"
echo
echo -e "${BLUE}Ubuntu/Debian with UFW:${NC}"
echo "  sudo ufw allow 8081/tcp"
echo "  sudo ufw allow 40401/tcp"
echo
echo -e "${BLUE}CentOS/RHEL with firewalld:${NC}"
echo "  sudo firewall-cmd --permanent --add-port=8081/tcp"
echo "  sudo firewall-cmd --permanent --add-port=40401/tcp"
echo "  sudo firewall-cmd --reload"
echo
echo -e "${BLUE}Router/NAT Configuration:${NC}"
echo "If behind a router, forward these ports to your server IP: $P2P_IP"
echo
echo -e "${BLUE}Useful Commands:${NC}"
echo "  • Check service status: sudo systemctl status aztec.service"
echo "  • View logs: sudo journalctl -u aztec.service -f"
echo "  • Restart service: sudo systemctl restart aztec.service"
echo "  • Stop service: sudo systemctl stop aztec.service"
echo
echo -e "${BLUE}Configuration file location:${NC} $AZTEC_DIR/.env"
echo -e "${BLUE}Binary location:${NC} $AZTEC_DIR/bin/aztec"
echo
log "Aztec Validator Node setup completed successfully!"
echo
warn "Remember to:"
warn "1. Configure your firewall as shown above"
warn "2. Set up port forwarding if behind NAT"
warn "3. Monitor the service logs for any issues"
warn "4. Keep your validator private key secure"
