#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
cleanup() {
    if [ -f "/tmp/get-docker.sh" ]; then
        rm -f /tmp/get-docker.sh
    fi
    if [ -f "/tmp/bin.tar.gz" ]; then
        rm -f /tmp/bin.tar.gz
    fi
}

trap cleanup EXIT

# Validation functions
validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        return 1
    fi
    return 0
}

validate_ethereum_address() {
    local address="$1"
    if [[ ! "$address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        return 1
    fi
    return 0
}

validate_private_key() {
    local key="$1"
    # Remove 0x prefix if present
    key="${key#0x}"
    if [[ ! "$key" =~ ^[a-fA-F0-9]{64}$ ]]; then
        return 1
    fi
    return 0
}

# Main variables
USER=$(whoami)
SCRIPT_PATH=$(readlink -f "$0")
AZTEC_DIR="/home/$USER/.aztec"
ENV_FILE="$AZTEC_DIR/.env"
SERVICE_NAME="aztec.service"

# Check if running as root
if [ "$USER" = "root" ]; then
    log_error "This script should not be run as root. Please run as a regular user."
    exit 1
fi

log_info "Starting Aztec Validator Node Setup"
log_info "User: $USER"
log_info "Script path: $SCRIPT_PATH"

# Step 1: Check and install Docker
log_info "Step 1: Checking Docker installation"
if command -v docker &> /dev/null; then
    log_success "Docker is already installed. Version: $(docker --version)"
else
    log_info "Installing Docker..."
    if ! curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        log_error "Failed to download Docker installation script"
        exit 1
    fi
    
    if ! sh /tmp/get-docker.sh; then
        log_error "Docker installation failed"
        exit 1
    fi
    
    rm -f /tmp/get-docker.sh
    log_success "Docker installed successfully"
fi

# Check if we need to handle Docker group (only on first run)
if [ -z "$REENTERED" ]; then
    log_info "Step 2: Setting up Docker group and permissions"

    # Create docker group if not exists
    if ! getent group docker > /dev/null 2>&1; then
        log_info "Creating docker group..."
        sudo groupadd docker
        log_success "Docker group created"
    else
        log_success "Docker group already exists"
    fi

    # Check if user is already in docker group
    if ! groups $USER | grep -q docker; then
        log_info "Adding user $USER to docker group..."
        sudo usermod -aG docker $USER
        log_success "User $USER added to docker group"
        
        log_warning "Switching shell to activate docker group..."
        echo
        log_info "⚠️  This will continue the script in a new shell with docker group enabled."
        echo
        
        # Re-run script in a new shell with the docker group applied
        exec sg docker "REENTERED=1 bash \"$SCRIPT_PATH\""
        exit 0
    else
        log_success "User $USER is already in docker group"
        export REENTERED=1
    fi
fi

# ------------ CONTINUE HERE after REENTERED ------------

log_success "✅ Docker group is active in current shell. Continuing setup..."

# Step 3: Setup Aztec directory and download binaries
log_info "Step 3: Setting up Aztec directory and downloading binaries"

# Create directory with proper permissions
mkdir -p "$AZTEC_DIR"
chmod 755 "$AZTEC_DIR"

if [ -f "$AZTEC_DIR/bin/aztec" ]; then
    log_success "Aztec binary already exists. Skipping download."
else
    log_info "Downloading Aztec binaries..."
    
    if ! curl -sL https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/bin.tar.gz -o /tmp/bin.tar.gz; then
        log_error "Failed to download Aztec binaries"
        exit 1
    fi
    
    if ! tar -xzf /tmp/bin.tar.gz -C "$AZTEC_DIR"; then
        log_error "Failed to extract Aztec binaries"
        exit 1
    fi
    
    rm -f /tmp/bin.tar.gz
    chmod +x "$AZTEC_DIR/bin/aztec"
    log_success "Aztec binaries downloaded and installed successfully"
fi

# Step 4: Create environment configuration
log_info "Step 4: Creating environment configuration"

# Get public IP with fallback
log_info "Detecting public IP address..."
P2P_IP=$(curl -s --connect-timeout 10 https://api.ipify.org 2>/dev/null || curl -s --connect-timeout 10 https://ipv4.icanhazip.com 2>/dev/null || echo "")

if [ -z "$P2P_IP" ]; then
    log_warning "Could not auto-detect public IP. Please enter manually."
    while true; do
        read -p "Enter your public IP address: " P2P_IP
        if [[ "$P2P_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            break
        else
            log_error "Invalid IP address format. Please try again."
        fi
    done
else
    log_success "Detected public IP: $P2P_IP"
fi

# Backup existing config if it exists
if [ -f "$ENV_FILE" ]; then
    backup_file="${ENV_FILE}.backup.$(date +%s)"
    cp "$ENV_FILE" "$backup_file"
    log_info "Existing configuration backed up to: $backup_file"
fi

# Input validation and collection
echo
log_info "Please provide the following configuration parameters:"

# ETHEREUM_HOSTS
while true; do
    read -p "Enter ETHEREUM_HOSTS (comma-separated URLs): " ETHEREUM_HOSTS
    if [ -z "$ETHEREUM_HOSTS" ]; then
        log_error "ETHEREUM_HOSTS cannot be empty"
        continue
    fi
    
    # Validate URLs
    valid_urls=true
    IFS=',' read -ra URLS <<< "$ETHEREUM_HOSTS"
    for url in "${URLS[@]}"; do
        url=$(echo "$url" | xargs) # trim whitespace
        if ! validate_url "$url"; then
            log_error "Invalid URL format: $url"
            valid_urls=false
            break
        fi
    done
    
    if $valid_urls; then
        break
    fi
done

# L1_CONSENSUS_HOST_URLS
while true; do
    read -p "Enter L1_CONSENSUS_HOST_URLS (comma-separated URLs): " L1_CONSENSUS_HOST_URLS
    if [ -z "$L1_CONSENSUS_HOST_URLS" ]; then
        log_error "L1_CONSENSUS_HOST_URLS cannot be empty"
        continue
    fi
    
    # Validate URLs
    valid_urls=true
    IFS=',' read -ra URLS <<< "$L1_CONSENSUS_HOST_URLS"
    for url in "${URLS[@]}"; do
        url=$(echo "$url" | xargs) # trim whitespace
        if ! validate_url "$url"; then
            log_error "Invalid URL format: $url"
            valid_urls=false
            break
        fi
    done
    
    if $valid_urls; then
        break
    fi
done

# VALIDATOR_PRIVATE_KEY (secure input)
while true; do
    read -s -p "Enter VALIDATOR_PRIVATE_KEY (input hidden): " VALIDATOR_PRIVATE_KEY
    echo
    
    if [ -z "$VALIDATOR_PRIVATE_KEY" ]; then
        log_error "VALIDATOR_PRIVATE_KEY cannot be empty"
        continue
    fi
    
    if ! validate_private_key "$VALIDATOR_PRIVATE_KEY"; then
        log_error "Invalid private key format. Must be 64 hex characters (with or without 0x prefix)"
        continue
    fi
    
    # Ensure 0x prefix
    if [[ ! "$VALIDATOR_PRIVATE_KEY" =~ ^0x ]]; then
        VALIDATOR_PRIVATE_KEY="0x$VALIDATOR_PRIVATE_KEY"
    fi
    
    break
done

# COINBASE
while true; do
    read -p "Enter COINBASE address: " COINBASE
    if [ -z "$COINBASE" ]; then
        log_error "COINBASE address cannot be empty"
        continue
    fi
    
    if ! validate_ethereum_address "$COINBASE"; then
        log_error "Invalid Ethereum address format"
        continue
    fi
    
    break
done

# Create environment file with secure permissions
cat > "$ENV_FILE" <<EOF
# Aztec Validator Configuration
# Generated on: $(date)

ETHEREUM_HOSTS=$ETHEREUM_HOSTS
L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS
VALIDATOR_PRIVATE_KEY=$VALIDATOR_PRIVATE_KEY
COINBASE=$COINBASE
P2P_IP=$P2P_IP
EOF

# Set secure permissions (only owner can read/write)
chmod 600 "$ENV_FILE"
log_success "Environment file created at: $ENV_FILE"

# Step 5: Create systemd service
log_info "Step 5: Creating systemd service"

# Check for existing service
if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME"; then
    log_info "Existing Aztec service found. Stopping and removing..."
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    log_success "Existing service stopped and disabled"
fi

# Create service file
sudo tee "/etc/systemd/system/$SERVICE_NAME" > /dev/null <<EOF
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
EnvironmentFile=$ENV_FILE
ExecStart=$AZTEC_DIR/bin/aztec start --node --archiver --sequencer \\
  --network alpha-testnet \\
  --l1-rpc-urls \${ETHEREUM_HOSTS} \\
  --l1-consensus-host-urls \${L1_CONSENSUS_HOST_URLS} \\
  --sequencer.validatorPrivateKey \${VALIDATOR_PRIVATE_KEY} \\
  --sequencer.coinbase \${COINBASE} \\
  --p2p.p2pIp \${P2P_IP} \\
  --p2p.p2pPort 40401 \\
  --port 8081
Restart=always
RestartSec=10
StartLimitInterval=0
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$AZTEC_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aztec-validator

[Install]
WantedBy=multi-user.target
EOF

log_success "Service file created"

# Configure and start service
log_info "Configuring and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

# Wait a moment and check service status
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_success "✅ Aztec validator service started successfully!"
else
    log_warning "Service may have issues starting. Checking status..."
    sudo systemctl status "$SERVICE_NAME" --no-pager
fi

# Final instructions
echo
echo "==============================================="
log_success "🎉 Aztec Validator Setup Complete!"
echo "==============================================="
echo
log_warning "🚧 IMPORTANT: Firewall Configuration Required"
echo "   You must open the following ports:"
echo "   • Port 8081 (Aztec API)"
echo "   • Port 40401 (P2P Network)"
echo
echo "   Run these commands to configure UFW:"
echo "   ${BLUE}sudo ufw allow 8081/tcp${NC}"
echo "   ${BLUE}sudo ufw allow 40401/tcp${NC}"
echo
log_info "📋 Useful Commands:"
echo "   • Check service status: ${BLUE}sudo systemctl status $SERVICE_NAME${NC}"
echo "   • View logs: ${BLUE}sudo journalctl -fu $SERVICE_NAME${NC}"
echo "   • Restart service: ${BLUE}sudo systemctl restart $SERVICE_NAME${NC}"
echo "   • Stop service: ${BLUE}sudo systemctl stop $SERVICE_NAME${NC}"
echo
log_info "📁 Configuration files:"
echo "   • Environment: ${BLUE}$ENV_FILE${NC}"
echo "   • Service: ${BLUE}/etc/systemd/system/$SERVICE_NAME${NC}"
echo "   • Binary: ${BLUE}$AZTEC_DIR/bin/aztec${NC}"
echo
log_success "Setup completed successfully! 🚀"
