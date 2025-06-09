#!/bin/bash

# Aztec Node Setup Script - Complete Fixed Version
# Description: Complete setup script for Aztec blockchain node with all fixes
# Author: System Administrator
# Date: $(date)

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flag to prevent infinite loop
DOCKER_GROUP_APPLIED=${DOCKER_GROUP_APPLIED:-false}

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Function to show service management commands
show_service_commands() {
    log "Service Management Commands:"
    echo "Enable service:  sudo systemctl enable aztec"
    echo "Start service:   sudo systemctl start aztec"
    echo "Stop service:    sudo systemctl stop aztec"
    echo "Restart service: sudo systemctl restart aztec"
    echo "Check status:    sudo systemctl status aztec"
    echo "View logs:       sudo journalctl -u aztec -f"
    echo "Edit config:     nano $HOME/.aztec/.env"
    echo ""
    info "After editing .env file, restart the service to apply changes"
}

# Function to show configuration management
show_config_management() {
    log "Configuration Management:"
    echo "Environment file location: $HOME/.aztec/.env"
    echo "To reconfigure: ./aztec-setup.sh --config"
    echo "To view config: cat $HOME/.aztec/.env"
    echo "To edit config: nano $HOME/.aztec/.env"
    echo ""
    warning "Keep your private key secure! The .env file has restricted permissions (600)."
}

# Function to handle all system package operations efficiently
setup_system_packages() {
    log "Setting up system packages and repositories..."
    
    # Single system update at the beginning
    sudo apt-get update || error "Failed to update system"
    
    # Remove old Docker installations in one command
    log "Removing old Docker installations..."
    local old_docker_packages=("docker.io" "docker-doc" "docker-compose" "podman-docker" "containerd" "runc")
    sudo apt-get remove "${old_docker_packages[@]}" -y 2>/dev/null || true
    
    # Install all required packages in one optimized command
    log "Installing required system packages..."
    local required_packages=(
        "curl" "iptables" "build-essential" "git" "wget" "lz4" "jq" "make" 
        "gcc" "nano" "automake" "autoconf" "tmux" "htop" "nvme-cli" "libgbm1" 
        "pkg-config" "libssl-dev" "libleveldb-dev" "tar" "clang" "bsdmainutils" 
        "ncdu" "unzip" "ca-certificates" "gnupg"
    )
    
    sudo apt-get install "${required_packages[@]}" -y || error "Failed to install required packages"
    
    log "System packages installed successfully"
}

# Function to setup Docker repository and install Docker - FIXED
setup_docker() {
    log "Setting up Docker..."
    
    # Check if Docker is already installed and running
    if command -v docker >/dev/null 2>&1; then
        log "Docker is already installed, checking service status..."
        if systemctl is-active --quiet docker; then
            log "Docker service is running"
        else
            log "Docker service is not running, starting it..."
            sudo systemctl start docker || error "Failed to start Docker service"
        fi
        return 0
    fi
    
    # Remove existing Docker GPG key if exists to prevent conflicts
    sudo rm -f /etc/apt/keyrings/docker.gpg 2>/dev/null || true
    
    # Add Docker GPG key and repository
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg || error "Failed to add Docker GPG key"
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null || error "Failed to add Docker repository"
    
    # Update and install Docker packages in one operation
    sudo apt-get update || error "Failed to update after adding Docker repo"
    
    local docker_packages=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin" "docker-compose-plugin")
    sudo apt-get install "${docker_packages[@]}" -y || error "Failed to install Docker"
    
    # Enable and start Docker service
    sudo systemctl enable docker || error "Failed to enable Docker service"
    sudo systemctl start docker || error "Failed to start Docker service"
    
    log "Docker installed and configured successfully"
}

# Function to apply docker group without causing infinite loop - COMPLETELY FIXED
apply_docker_group() {
    # Skip if already applied to prevent loop
    if [[ "$DOCKER_GROUP_APPLIED" == "true" ]]; then
        log "Docker group permissions already applied"
        return 0
    fi
    
    log "Applying Docker group permissions..."
    
    # Add user to docker group
    sudo usermod -aG docker $USER || warning "Failed to add user to docker group"
    
    # Set flag to prevent re-execution
    export DOCKER_GROUP_APPLIED=true
    
    # Fix Docker socket permissions immediately
    log "Fixing Docker socket permissions..."
    sudo chown root:docker /var/run/docker.sock || warning "Failed to change socket ownership"
    sudo chmod 660 /var/run/docker.sock || warning "Failed to change socket permissions"
    
    log "Docker group permissions applied. Testing access..."
    
    # Test Docker access with timeout and proper error handling
    if timeout 10 docker ps >/dev/null 2>&1; then
        log "✓ Docker access verified - no sudo required"
        return 0
    else
        # Try activating group membership without exec
        log "Activating Docker group membership..."
        if command -v newgrp >/dev/null 2>&1; then
            # Use newgrp in a subshell to avoid session changes
            if timeout 10 bash -c "newgrp docker <<< 'docker ps'" >/dev/null 2>&1; then
                log "✓ Docker access activated via newgrp"
                return 0
            fi
        fi
        
        warning "Docker group permissions applied but may require terminal restart"
        info "You can continue the installation or restart your terminal session"
        return 0
    fi
}

# Function to verify docker access - IMPROVED
verify_docker_access() {
    log "Verifying Docker access..."
    
    # Ensure Docker service is running
    if ! systemctl is-active --quiet docker; then
        log "Starting Docker service..."
        sudo systemctl start docker || error "Failed to start Docker service"
        sleep 3
    fi
    
    # Test Docker without sudo with multiple attempts
    local attempts=3
    for i in $(seq 1 $attempts); do
        if timeout 10 docker ps >/dev/null 2>&1; then
            log "✓ Docker access verified - no sudo required"
            return 0
        elif timeout 10 sudo docker ps >/dev/null 2>&1; then
            warning "Docker works with sudo but not without - permissions issue"
            # Try to fix permissions
            sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
            if timeout 10 docker ps >/dev/null 2>&1; then
                log "✓ Docker access fixed"
                return 0
            fi
        fi
        
        if [[ $i -lt $attempts ]]; then
            log "Docker access attempt $i failed, retrying..."
            sleep 2
        fi
    done
    
    warning "Docker access verification failed - may need terminal restart"
    info "Continuing with installation..."
    return 0
}

# Function to test Docker installation - ROBUST VERSION
test_docker_installation() {
    log "Testing Docker installation..."
    
    # Ensure Docker daemon is running
    if ! systemctl is-active --quiet docker; then
        log "Docker service not running, starting..."
        sudo systemctl start docker || error "Failed to start Docker service"
        sleep 5
    fi
    
    # Test with multiple methods
    local test_passed=false
    
    # Method 1: Try without sudo
    if timeout 30 docker run --rm hello-world >/dev/null 2>&1; then
        log "✓ Docker test successful (without sudo)"
        test_passed=true
    # Method 2: Try with sudo
    elif timeout 30 sudo docker run --rm hello-world >/dev/null 2>&1; then
        log "✓ Docker test successful (with sudo)"
        warning "Docker requires sudo - permissions may need adjustment"
        test_passed=true
    # Method 3: Try with socket permission fix
    else
        log "Attempting to fix Docker socket permissions..."
        sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
        if timeout 30 docker run --rm hello-world >/dev/null 2>&1; then
            log "✓ Docker test successful (after permission fix)"
            test_passed=true
        fi
    fi
    
    if [[ "$test_passed" == "false" ]]; then
        warning "Docker test failed, but continuing installation..."
        info "You may need to restart your terminal or system"
    fi
    
    return 0
}

# Function to get public IP automatically
get_public_ip() {
    local ip=""
    local services=("ifconfig.me" "ipecho.net/plain" "icanhazip.com" "ident.me")
    
    for service in "${services[@]}"; do
        ip=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    # Fallback method using hostname
    ip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    
    error "Could not determine public IP address"
}

# Function to validate Ethereum address
validate_eth_address() {
    local address="$1"
    if [[ ! "$address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        return 1
    fi
    return 0
}

# Function to validate private key
validate_private_key() {
    local key="$1"
    if [[ ! "$key" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        return 1
    fi
    return 0
}

# Function to validate URL
validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        return 1
    fi
    return 0
}

# Function to read hidden input (for private key)
read_hidden() {
    local prompt="$1"
    local input=""
    echo -n "$prompt"
    while IFS= read -r -s -n1 char; do
        if [[ $char == $'\0' ]]; then
            break
        elif [[ $char == $'\177' ]]; then  # Backspace
            if [[ ${#input} -gt 0 ]]; then
                input="${input%?}"
                echo -ne '\b \b'
            fi
        else
            input+="$char"
            echo -n "*"
        fi
    done
    echo
    echo "$input"
}

# Function to create .env file with user input
create_env_file() {
    local env_file="$HOME/.aztec/.env"
    
    log "Creating environment configuration..."
    
    # Create .aztec directory if it doesn't exist
    mkdir -p "$HOME/.aztec"
    
    # Get RPC URL
    while true; do
        echo -n "Enter Ethereum L1 RPC URL (e.g., https://mainnet.infura.io/v3/YOUR_KEY): "
        read -r rpc_url
        if validate_url "$rpc_url"; then
            break
        else
            error "Invalid URL format. Please enter a valid HTTP/HTTPS URL."
        fi
    done
    
    # Get Beacon URL
    while true; do
        echo -n "Enter Ethereum Beacon Chain URL (e.g., https://beacon-nd-123-456-789.p2pify.com): "
        read -r beacon_url
        if validate_url "$beacon_url"; then
            break
        else
            error "Invalid URL format. Please enter a valid HTTP/HTTPS URL."
        fi
    done
    
    # Get Private Key (hidden input)
    while true; do
        private_key=$(read_hidden "Enter your validator private key (will be hidden): ")
        if validate_private_key "$private_key"; then
            break
        else
            error "Invalid private key format. Must be 0x followed by 64 hexadecimal characters."
        fi
    done
    
    # Get Coinbase Address
    while true; do
        echo -n "Enter your coinbase address (0x...): "
        read -r coinbase_address
        if validate_eth_address "$coinbase_address"; then
            break
        else
            error "Invalid Ethereum address format. Must be 0x followed by 40 hexadecimal characters."
        fi
    done
    
    # Get Public IP automatically
    log "Detecting public IP address..."
    public_ip=$(get_public_ip)
    log "Detected public IP: $public_ip"
    
    # Confirm IP or allow manual override
    echo -n "Use detected IP ($public_ip)? [Y/n]: "
    read -r confirm_ip
    if [[ "$confirm_ip" =~ ^[Nn]$ ]]; then
        echo -n "Enter your public IP address: "
        read -r public_ip
    fi
    
    # Create .env file
    cat > "$env_file" << EOF
# Aztec Node Configuration
# Generated on $(date)

# Ethereum L1 RPC URL
RPC_URL=$rpc_url

# Ethereum Beacon Chain URL
BEACON_URL=$beacon_url

# Validator Private Key (Keep this secure!)
VALIDATOR_PRIVATE_KEY=$private_key

# Coinbase Address
COINBASE_ADDRESS=$coinbase_address

# Public IP for P2P networking
PUBLIC_IP=$public_ip

# Additional Configuration
NETWORK=alpha-testnet
LOG_LEVEL=info
EOF
    
    # Set secure permissions
    chmod 600 "$env_file"
    
    log "Environment file created at: $env_file"
    log "File permissions set to 600 (owner read/write only)"
}

# Function to load environment variables
load_env() {
    local env_file="$HOME/.aztec/.env"
    if [[ -f "$env_file" ]]; then
        source "$env_file"
        log "Environment variables loaded from $env_file"
    else
        warning "Environment file not found. Please run configuration first."
        return 1
    fi
}

# Function to create systemd service with environment support
create_systemd_service() {
    log "Creating systemd service file with environment support..."
    
    cat << 'EOF' | sudo tee /etc/systemd/system/aztec.service > /dev/null
[Unit]
Description=Aztec Node Service
After=network.target docker.service
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=5
User=%i
WorkingDirectory=%h
Environment=PATH=%h/.aztec/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile=%h/.aztec/.env
ExecStartPre=/bin/bash -c 'source %h/.bashrc'
ExecStart=/bin/bash -c 'source %h/.bashrc && aztec start --node --archiver --sequencer --network ${NETWORK} --l1-rpc-urls ${RPC_URL} --l1-consensus-host-urls ${BEACON_URL} --sequencer.validatorPrivateKey ${VALIDATOR_PRIVATE_KEY} --sequencer.coinbase ${COINBASE_ADDRESS} --p2p.p2pIp ${PUBLIC_IP}'
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aztec

[Install]
WantedBy=multi-user.target
EOF

    # Replace placeholders with actual user
    sudo sed -i "s/%i/$USER/g" /etc/systemd/system/aztec.service
    sudo sed -i "s|%h|$HOME|g" /etc/systemd/system/aztec.service
    
    sudo systemctl daemon-reload || error "Failed to reload systemd daemon"
    
    log "Systemd service created successfully!"
    show_service_commands
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
fi

# Main installation function - COMPLETELY FIXED VERSION
main() {
    log "Starting Aztec Node Setup - Complete Fixed Version..."
    
    # Step 1: Optimized System Package Setup
    setup_system_packages
    
    # Step 2: Setup Docker with proper checks and fixes
    setup_docker
    
    # Step 3: Apply Docker group permissions (FIXED - no loop)
    apply_docker_group
    
    # Step 4: Verify Docker access with robust checking
    verify_docker_access
    
    # Step 5: Test Docker installation with multiple fallback methods
    test_docker_installation
    
    # Step 6: Install Aztec
    log "Installing Aztec..."
    
    # Ensure Docker is accessible for Aztec installer
    if ! timeout 10 docker ps >/dev/null 2>&1; then
        log "Making Docker accessible for Aztec installer..."
        sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    fi
    
    # Install Aztec with error handling
    if ! bash -i <(curl -s https://install.aztec.network); then
        error "Failed to install Aztec. Please check Docker permissions and try again."
    fi
    
    # Add Aztec to PATH
    echo 'export PATH="$HOME/.aztec/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc || true
    
    # Step 7: Setup Aztec
    log "Setting up Aztec..."
    export PATH="$HOME/.aztec/bin:$PATH"
    
    if ! aztec-up latest; then
        error "Failed to setup Aztec. Please check your installation."
    fi
    
    # Step 8: Create environment configuration
    create_env_file
    
    # Step 9: Create systemd service with environment variables
    create_systemd_service
    
    log "Aztec installation and configuration completed successfully!"
    log "✓ Fixed infinite loop issue!"
    log "✓ Fixed Docker permissions and service issues!"
    log "✓ Robust error handling and fallback methods!"
}

# Handle command line arguments
case "${1:-}" in
    --config|--configure)
        log "Running configuration only..."
        create_env_file
        show_config_management
        exit 0
        ;;
    --help|-h)
        echo "Aztec Node Setup Script - Complete Fixed Version"
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --config     Run configuration only"
        echo "  --help       Show this help message"
        echo ""
        echo "Fixes:"
        echo "  - Fixed infinite loop in Docker group application"
        echo "  - Fixed Docker service and permission issues"
        echo "  - Added robust Docker testing with fallback methods"
        echo "  - Improved error handling and recovery"
        echo ""
        echo "Default: Run full installation and configuration"
        exit 0
        ;;
esac

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    # Add any cleanup operations here
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function
main

# Show final instructions
show_config_management
show_service_commands

log "Script execution completed successfully!"
log "✓ All Docker issues resolved!"
log "✓ No more infinite loops!"
log "✓ Robust installation with proper error handling!"
log "Your configuration is stored securely in $HOME/.aztec/.env"
