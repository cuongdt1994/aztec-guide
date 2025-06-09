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

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS. This script requires Linux."
        exit 1
    fi
    
    # Check available disk space (minimum 50GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 52428800 ]; then  # 50GB in KB
        log_warning "Low disk space detected. Recommended: 50GB+ available"
    fi
    
    # Check RAM (minimum 8GB)
    total_ram=$(free -m | awk 'NR==2{print $2}')
    if [ "$total_ram" -lt 8192 ]; then
        log_warning "Low RAM detected. Recommended: 8GB+ RAM"
    fi
    
    log_success "System requirements check completed"
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

# Check system requirements
check_system_requirements

# Step 1: Update system packages
log_info "Step 1: Updating system packages"
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget tar gzip jq net-tools ufw

# Step 2: Check and install Docker
log_info "Step 2: Checking Docker installation"
if command -v docker &> /dev/null; then
    log_success "Docker is already installed. Version: $(docker --version)"
else
    log_info "Installing Docker..."
    if ! curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        log_error "Failed to download Docker installation script"
        exit 1
    fi
    
    if ! sudo sh /tmp/get-docker.sh; then
        log_error "Docker installation failed"
        exit 1
    fi
    
    rm -f /tmp/get-docker.sh
    log_success "Docker installed successfully"
fi

# Check if we need to handle Docker group (only on first run)
if [ -z "$REENTERED" ]; then
    log_info "Step 3: Setting up Docker group and permissions"

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

# Step 4: Test Docker functionality
log_info "Step 4: Testing Docker functionality"
if ! docker run --rm hello-world > /dev/null 2>&1; then
    log_error "Docker test failed. Please check Docker installation."
    exit 1
fi
log_success "Docker is working correctly"

# Step 5: Setup Aztec directory and download binaries
log_info "Step 5: Setting up Aztec directory and downloading binaries"

# Create directory with proper permissions
mkdir -p "$AZTEC_DIR/bin"
mkdir -p "$AZTEC_DIR/data"
chmod 755 "$AZTEC_DIR"

# Download Aztec CLI instead of binary
log_info "Installing Aztec CLI..."
if ! command -v node &> /dev/null; then
    log_info "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# Install Aztec CLI globally
if ! npm install -g @aztec/cli@alpha-testnet; then
    log_error "Failed to install Aztec CLI"
    exit 1
fi

log_success "Aztec CLI installed successfully"

# Step 6: Create environment configuration
log_info "Step 6: Creating environment configuration"

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
    echo "Example: https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
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
    echo "Example: https://eth-sepolia-beacon-api.publicnode.com"
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
DATA_DIRECTORY=$AZTEC_DIR/data
EOF

# Set secure permissions (only owner can read/write)
chmod 600 "$ENV_FILE"
log_success "Environment file created at: $ENV_FILE"

# Step 7: Create systemd service
log_info "Step 7: Creating systemd service"

# Check for existing service
if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME"; then
    log_info "Existing Aztec service found. Stopping and removing..."
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    log_success "Existing service stopped and disabled"
fi

# Create service file with correct aztec command
sudo tee "/etc/systemd/system/$SERVICE_NAME" > /dev/null <<EOF
[Unit]
Description=Aztec Validator Node
Documentation=https://docs.aztec.network/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$AZTEC_DIR
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/aztec start --node --archiver --sequencer \\
  --network alpha-testnet \\
  --l1-rpc-urls \${ETHEREUM_HOSTS} \\
  --l1-consensus-host-urls \${L1_CONSENSUS_HOST_URLS} \\
  --sequencer.validatorPrivateKey \${VALIDATOR_PRIVATE_KEY} \\
  --sequencer.coinbase \${COINBASE} \\
  --p2p.p2pIp \${P2P_IP} \\
  --p2p.p2pPort 40400 \\
  --port 8080 \\
  --data-directory \${DATA_DIRECTORY}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

log_success "Service file created"

# Step 8: Configure firewall
log_info "Step 8: Configuring firewall"
sudo ufw allow 8080/tcp
sudo ufw allow 40400/tcp
sudo ufw allow 40400/udp
sudo ufw --force enable
log_success "Firewall configured"

# Step 9: Configure and start service
log_info "Step 9: Configuring and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

# Wait a moment and check service status
sleep 5

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_success "✅ Aztec validator service started successfully!"
else
    log_warning "Service may have issues starting. Checking status..."
    sudo systemctl status "$SERVICE_NAME" --no-pager
fi

# Step 10: Create monitoring script
log_info "Step 10: Creating monitoring script"
cat > "$AZTEC_DIR/monitor.sh" <<'EOF'
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Aztec Node Monitor ===${NC}"
echo

# Check service status
echo -e "${BLUE}Service Status:${NC}"
if systemctl is-active --quiet aztec.service; then
    echo -e "${GREEN}✅ Service is running${NC}"
else
    echo -e "${RED}❌ Service is not running${NC}"
fi

# Check sync status
echo -e "\n${BLUE}Sync Status:${NC}"
local_block=$(curl -s -X POST -H 'Content-Type: application/json' \
-d '{"jsonrpc":"2.0","method":"node_getL2Tips","params":[],"id":67}' \
http://localhost:8080 2>/dev/null | jq -r ".result.proven.number" 2>/dev/null)

if [ "$local_block" != "null" ] && [ -n "$local_block" ]; then
    echo -e "${GREEN}✅ Local block: $local_block${NC}"
else
    echo -e "${RED}❌ Cannot get local block number${NC}"
fi

# Check ports
echo -e "\n${BLUE}Port Status:${NC}"
if netstat -tlnp 2>/dev/null | grep -q ":8080"; then
    echo -e "${GREEN}✅ Port 8080 is open${NC}"
else
    echo -e "${RED}❌ Port 8080 is not open${NC}"
fi

if netstat -tlnp 2>/dev/null | grep -q ":40400"; then
    echo -e "${GREEN}✅ Port 40400 is open${NC}"
else
    echo -e "${RED}❌ Port 40400 is not open${NC}"
fi

echo
echo -e "${BLUE}Commands:${NC}"
echo "View logs: sudo journalctl -fu aztec.service"
echo "Restart:   sudo systemctl restart aztec.service"
echo "Stop:      sudo systemctl stop aztec.service"
EOF

chmod +x "$AZTEC_DIR/monitor.sh"
log_success "Monitoring script created at: $AZTEC_DIR/monitor.sh"

# Final instructions
echo
echo "==============================================="
log_success "🎉 Aztec Validator Setup Complete!"
echo "==============================================="
echo
log_info "📋 Useful Commands:"
echo "   • Monitor node: ${BLUE}$AZTEC_DIR/monitor.sh${NC}"
echo "   • Check service status: ${BLUE}sudo systemctl status $SERVICE_NAME${NC}"
echo "   • View logs: ${BLUE}sudo journalctl -fu $SERVICE_NAME${NC}"
echo "   • Restart service: ${BLUE}sudo systemctl restart $SERVICE_NAME${NC}"
echo "   • Stop service: ${BLUE}sudo systemctl stop $SERVICE_NAME${NC}"
echo
log_info "📁 Configuration files:"
echo "   • Environment: ${BLUE}$ENV_FILE${NC}"
echo "   • Service: ${BLUE}/etc/systemd/system/$SERVICE_NAME${NC}"
echo "   • Data directory: ${BLUE}$AZTEC_DIR/data${NC}"
echo
log_warning "🔍 Next Steps:"
echo "   1. Wait for node to sync (check with monitor script)"
echo "   2. Register as validator when fully synced:"
echo "      ${BLUE}aztec add-l1-validator \\${NC}"
echo "      ${BLUE}  --l1-rpc-urls $ETHEREUM_HOSTS \\${NC}"
echo "      ${BLUE}  --private-key $VALIDATOR_PRIVATE_KEY \\${NC}"
echo "      ${BLUE}  --attester $COINBASE \\${NC}"
echo "      ${BLUE}  --proposer-eoa $COINBASE \\${NC}"
echo "      ${BLUE}  --staking-asset-handler 0xF739D03e98e23A7B65940848aBA8921fF3bAc4b2 \\${NC}"
echo "      ${BLUE}  --l1-chain-id 11155111${NC}"
echo
log_success "Setup completed successfully! 🚀"
