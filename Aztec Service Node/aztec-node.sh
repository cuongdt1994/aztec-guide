#!/bin/bash

# Aztec Sequencer Node Setup Script
# Automated installation and configuration for Aztec Alpha Testnet

set -e

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_step() { echo -e "${PURPLE}🔧 $1${NC}"; }

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo privileges"
        exit 1
    fi
}

# Create project directory
setup_project_directory() {
    local install_dir="/root/.aztec"
    log_step "Setting up project directory: $install_dir"
    
    mkdir -p "$install_dir" && cd "$install_dir"
    PROJECT_PATH="$(pwd)"
    ENV_FILE="$PROJECT_PATH/.env"
    
    log_success "Project directory created at: $PROJECT_PATH"
}

# Validate and handle existing environment file
handle_existing_env() {
    if [ -f "$ENV_FILE" ]; then
        log_info "Found existing .env file, validating..."
        
        local env_valid=true
        while IFS='=' read -r key value || [ -n "$key" ]; do
            # Skip empty lines and comments
            [[ -z "$key" ]] && continue
            [[ "$key" =~ ^#.*$ ]] && continue
            [[ "$key" =~ ^[[:space:]]*$ ]] && continue
            
            # Check if value is empty (but allow empty values for some keys)
            if [[ -z "$value" && ! "$key" =~ ^(ADDITIONAL_SETTINGS|OPTIONAL_).*$ ]]; then
                env_valid=false
                break
            fi
        done < <(grep -v '^[[:space:]]*$' "$ENV_FILE")
        
        if [ "$env_valid" = true ]; then
            # Safely export variables
            set -a
            source "$ENV_FILE" 2>/dev/null || true
            set +a
            
            if [[ -n "$ETHEREUM_HOSTS" && -n "$L1_CONSENSUS_HOST_URLS" && 
                  -n "$VALIDATOR_PRIVATE_KEY" && -n "$VALIDATOR_ADDRESS" && 
                  -n "$P2P_IP" ]]; then
                
                echo -e "${CYAN}🔍 Valid configuration found:${NC}"
                echo "   • Ethereum RPC: ${ETHEREUM_HOSTS:0:50}..."
                echo "   • Beacon RPC: ${L1_CONSENSUS_HOST_URLS:0:50}..."
                echo "   • Validator Address: $VALIDATOR_ADDRESS"
                echo "   • P2P IP: $P2P_IP"
                
                read -p "$(echo -e ${CYAN}🔄 Reuse existing configuration? [y/N]: ${NC})" REUSE_ENV
                
                if [[ "$REUSE_ENV" =~ ^[Yy]$ ]]; then
                    log_success "Reusing existing configuration"
                    return 0
                fi
            fi
        else
            log_warning "Environment file contains invalid values"
        fi
        
        # Clear variables if not reusing
        unset ETHEREUM_HOSTS L1_CONSENSUS_HOST_URLS VALIDATOR_PRIVATE_KEY VALIDATOR_ADDRESS P2P_IP 2>/dev/null || true
    fi
}

# Collect configuration from user
collect_configuration() {
    log_step "Collecting node configuration"
    
    echo -e "${CYAN}📝 Please provide the following information:${NC}"
    
    if [ -z "$ETHEREUM_HOSTS" ]; then
        while [ -z "$ETHEREUM_HOSTS" ]; do
            read -p "🔗 Ethereum RPC URL (e.g., https://sepolia.infura.io/v3/YOUR_KEY): " ETHEREUM_HOSTS
            if [ -z "$ETHEREUM_HOSTS" ]; then
                log_warning "Ethereum RPC URL is required"
            fi
        done
    fi
    
    if [ -z "$L1_CONSENSUS_HOST_URLS" ]; then
        while [ -z "$L1_CONSENSUS_HOST_URLS" ]; do
            read -p "🔗 Beacon Chain RPC URL (e.g., https://beacon-sepolia.infura.io): " L1_CONSENSUS_HOST_URLS
            if [ -z "$L1_CONSENSUS_HOST_URLS" ]; then
                log_warning "Beacon Chain RPC URL is required"
            fi
        done
    fi
    
    if [ -z "$VALIDATOR_PRIVATE_KEY" ]; then
        echo -e "${YELLOW}⚠️  Keep your private key secure!${NC}"
        while [ -z "$VALIDATOR_PRIVATE_KEY" ]; do
            read -s -p "🔑 Validator Private Key (0x...): " VALIDATOR_PRIVATE_KEY
            echo
            if [ -z "$VALIDATOR_PRIVATE_KEY" ]; then
                log_warning "Validator private key is required"
            fi
        done
    fi
    
    if [ -z "$VALIDATOR_ADDRESS" ]; then
        while [ -z "$VALIDATOR_ADDRESS" ]; do
            read -p "🏦 Validator Ethereum Address (0x...): " VALIDATOR_ADDRESS
            if [ -z "$VALIDATOR_ADDRESS" ]; then
                log_warning "Validator address is required"
            fi
        done
    fi
    
    if [ -z "$P2P_IP" ]; then
        log_info "Detecting public IP address..."
        P2P_IP=$(timeout 10 curl -s ipv4.icanhazip.com 2>/dev/null || timeout 10 curl -s ifconfig.me 2>/dev/null || echo "")
        
        if [ -z "$P2P_IP" ]; then
            while [ -z "$P2P_IP" ]; do
                read -p "🌐 Enter your public IP address: " P2P_IP
                if [ -z "$P2P_IP" ]; then
                    log_warning "Public IP address is required"
                fi
            done
        else
            log_success "Detected public IP: $P2P_IP"
            read -p "$(echo -e ${CYAN}Use detected IP $P2P_IP? [Y/n]: ${NC})" USE_DETECTED_IP
            if [[ "$USE_DETECTED_IP" =~ ^[Nn]$ ]]; then
                while [ -z "$P2P_IP" ]; do
                    read -p "🌐 Enter your public IP address: " P2P_IP
                    if [ -z "$P2P_IP" ]; then
                        log_warning "Public IP address is required"
                    fi
                done
            fi
        fi
    fi
    
    # Validate inputs
    validate_configuration
}

# Validate configuration inputs
validate_configuration() {
    local errors=0
    
    if [[ ! "$ETHEREUM_HOSTS" =~ ^https?:// ]]; then
        log_error "Invalid Ethereum RPC URL format (must start with http:// or https://)"
        ((errors++))
    fi
    
    if [[ ! "$L1_CONSENSUS_HOST_URLS" =~ ^https?:// ]]; then
        log_error "Invalid Beacon RPC URL format (must start with http:// or https://)"
        ((errors++))
    fi
    
    if [[ ! "$VALIDATOR_PRIVATE_KEY" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        log_error "Invalid private key format (must be 0x followed by 64 hex characters)"
        ((errors++))
    fi
    
    if [[ ! "$VALIDATOR_ADDRESS" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        log_error "Invalid Ethereum address format (must be 0x followed by 40 hex characters)"
        ((errors++))
    fi
    
    # More flexible IP validation
    if [[ ! "$P2P_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address format"
        ((errors++))
    else
        # Validate IP octets
        IFS='.' read -ra OCTETS <<< "$P2P_IP"
        for octet in "${OCTETS[@]}"; do
            if [ "$octet" -gt 255 ]; then
                log_error "Invalid IP address: octet $octet is greater than 255"
                ((errors++))
                break
            fi
        done
    fi
    
    if [ $errors -gt 0 ]; then
        log_error "Configuration validation failed. Please check your inputs."
        exit 1
    fi
    
    log_success "Configuration validated successfully"
}

# Install system dependencies
install_dependencies() {
    log_step "Installing system dependencies"
    
    # Update package list
    if ! apt update; then
        log_error "Failed to update package list"
        exit 1
    fi
    
    # Upgrade system (with timeout)
    if ! timeout 300 apt upgrade -y; then
        log_warning "System upgrade timed out or failed, continuing..."
    fi
    
    local packages=(
        curl iptables build-essential git wget lz4 jq make gcc nano
        automake autoconf tmux htop nvme-cli pkg-config
        libssl-dev libleveldb-dev tar clang bsdmainutils ncdu unzip
        ca-certificates gnupg software-properties-common apt-transport-https
    )
    
    # Install packages with error handling
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log_info "Installing $package..."
            if ! apt install -y "$package"; then
                log_warning "Failed to install $package, continuing..."
            fi
        fi
    done
    
    log_success "System dependencies installation completed"
}

# Install Docker
install_docker() {
    log_step "Setting up Docker"
    
    if command -v docker &> /dev/null; then
        log_info "Docker already installed, checking version..."
        docker --version
        
        # Test Docker
        if docker info &>/dev/null; then
            log_success "Docker is working properly"
            return 0
        else
            log_warning "Docker daemon is not running, attempting to start..."
            systemctl start docker
        fi
    fi
    
    # Remove old Docker packages
    local old_packages=(docker.io docker-doc docker-compose podman-docker containerd runc)
    for pkg in "${old_packages[@]}"; do
        apt-get remove -y "$pkg" 2>/dev/null || true
    done
    
    # Create keyring directory
    install -m 0755 -d /etc/apt/keyrings
    
    # Add Docker's official GPG key with error handling
    if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
        log_error "Failed to add Docker GPG key"
        exit 1
    fi
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Detect OS version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        VERSION_CODENAME=${VERSION_CODENAME:-$(lsb_release -cs)}
    else
        VERSION_CODENAME=$(lsb_release -cs)
    fi
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    if ! apt update; then
        log_error "Failed to update package list after adding Docker repository"
        exit 1
    fi
    
    if ! apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        log_error "Failed to install Docker packages"
        exit 1
    fi
    
    # Enable and start Docker service
    systemctl enable docker
    systemctl start docker
    
    # Wait for Docker to start
    sleep 5
    
    # Test Docker installation
    if timeout 30 docker run --rm hello-world &>/dev/null; then
        log_success "Docker installed and tested successfully"
    else
        log_warning "Docker installation completed but test failed"
        log_info "This might be normal on some systems. Continuing..."
    fi
}

# Install Aztec CLI
install_aztec_cli() {
    log_step "Setting up Aztec CLI"
    
    # Set up Aztec directory - sử dụng /root/.aztec làm thư mục chính
    AZTEC_DIR="/root/.aztec"
    mkdir -p "$AZTEC_DIR/bin"
    
    if command -v aztec &> /dev/null; then
        log_info "Aztec CLI found, updating to latest version..."
        if command -v aztec-up &> /dev/null; then
            aztec-up alpha-testnet
        else
            log_warning "aztec-up not found, reinstalling..."
        fi
    else
        log_info "Installing Aztec CLI..."
        # Download and install with error handling
        if ! curl -s https://install.aztec.network | bash; then
            log_error "Failed to install Aztec CLI"
            exit 1
        fi
    fi
    
    # Add to PATH for current session
    export PATH="$PATH:$AZTEC_DIR/bin"
    
    # Add to bashrc if not already present
    if ! grep -q "/.aztec/bin" ~/.bashrc; then
        echo 'export PATH="$PATH:/root/.aztec/bin"' >> ~/.bashrc
    fi
    
    log_success "Aztec CLI setup completed"
}

# Create environment file
create_env_file() {
    log_step "Creating environment configuration"
    
    # Backup existing env file
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "$ENV_FILE.backup.$(date +%s)"
        log_info "Backed up existing environment file"
    fi
    
    cat > "$ENV_FILE" << EOF
# Aztec Sequencer Configuration
# Generated on $(date)

# Network Configuration
ETHEREUM_HOSTS=$ETHEREUM_HOSTS
L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS

# Validator Configuration
VALIDATOR_PRIVATE_KEY=$VALIDATOR_PRIVATE_KEY
VALIDATOR_ADDRESS=$VALIDATOR_ADDRESS

# P2P Configuration
P2P_IP=$P2P_IP

# Additional Settings
AZTEC_NETWORK=alpha-testnet
EOF
    
    chmod 600 "$ENV_FILE"  # Secure the environment file
    log_success "Environment file created and secured"
}

# Setup systemd service
setup_systemd_service() {
    echo -e "${CYAN}🛠️  Setting up Aztec as a systemd service...${NC}"
    echo "   This will allow automatic startup and better process management."
    
    log_step "Creating systemd service"
    
    # Create service file with better error handling
    cat > /etc/systemd/system/aztec.service << EOF
[Unit]
Description=Aztec Sequencer Node
Documentation=https://docs.aztec.network/
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/.aztec
EnvironmentFile=/root/.aztec/.env
Environment=HOME=/root
ExecStart=/root/.aztec/bin/aztec start \\
    --node \\
    --archiver \\
    --sequencer \\
    --network \${AZTEC_NETWORK} \\
    --l1-rpc-urls=\${ETHEREUM_HOSTS} \\
    --l1-consensus-host-urls=\${L1_CONSENSUS_HOST_URLS} \\
    --sequencer.validatorPrivateKey=\${VALIDATOR_PRIVATE_KEY} \\
    --sequencer.coinbase=\${VALIDATOR_ADDRESS} \\
    --p2p.p2pIp=\${P2P_IP}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload and enable service
    systemctl daemon-reload
    systemctl enable aztec
    
    echo -e "${CYAN}🚀 Starting the service...${NC}"
    
    if systemctl start aztec; then
        log_success "Aztec sequencer service started"
        
        # Wait a moment for service to initialize
        sleep 5
        
        # Show service status
        echo -e "\n${CYAN}📊 Service Status:${NC}"
        systemctl status aztec --no-pager -l
    else
        log_error "Failed to start Aztec service"
        log_info "Check logs with: journalctl -u aztec -f"
    fi
    
    print_service_commands
}

# Print service management commands
print_service_commands() {
    echo -e "\n${CYAN}🔧 Service Management Commands:${NC}"
    echo "   • Start service:    systemctl start aztec"
    echo "   • Stop service:     systemctl stop aztec"
    echo "   • Restart service:  systemctl restart aztec"
    echo "   • Check status:     systemctl status aztec"
    echo "   • View logs:        journalctl -u aztec -f"
    echo "   • Disable service:  systemctl disable aztec"
}

# Print manual run commands
print_manual_commands() {
    echo -e "\n${CYAN}🚀 Manual Run Command:${NC}"
    echo "cd /root/.aztec && source .env"
    echo "export PATH=\"\$PATH:/root/.aztec/bin\""
    echo "aztec start --node --archiver --sequencer \\"
    echo "  --network alpha-testnet \\"
    echo "  --l1-rpc-urls=\$ETHEREUM_HOSTS \\"
    echo "  --l1-consensus-host-urls=\$L1_CONSENSUS_HOST_URLS \\"
    echo "  --sequencer.validatorPrivateKey=\$VALIDATOR_PRIVATE_KEY \\"
    echo "  --sequencer.coinbase=\$VALIDATOR_ADDRESS \\"
    echo "  --p2p.p2pIp=\$P2P_IP"
}

# Print final summary
print_summary() {
    echo -e "\n${GREEN}🎉 Aztec Sequencer Setup Complete!${NC}"
    echo -e "\n${CYAN}📋 Configuration Summary:${NC}"
    echo "   • Project Path: /root/.aztec"
    echo "   • Environment File: /root/.aztec/.env"
    echo "   • Network: Alpha Testnet"
    echo "   • Validator Address: $VALIDATOR_ADDRESS"
    echo "   • P2P IP: $P2P_IP"
    
    echo -e "\n${CYAN}📚 Useful Resources:${NC}"
    echo "   • Documentation: https://docs.aztec.network/"
    echo "   • Discord: https://discord.gg/aztec"
    echo "   • GitHub: https://github.com/AztecProtocol/aztec-packages"
    
    echo -e "\n${YELLOW}⚠️  Important Notes:${NC}"
    echo "   • Keep your private key secure and never share it"
    echo "   • Monitor your node regularly for optimal performance"
    echo "   • Ensure your server has adequate resources (CPU, RAM, storage)"
    echo "   • Keep your system and Aztec CLI updated"
    echo "   • Check logs regularly: journalctl -u aztec -f"
}

# Error handling function
handle_error() {
    log_error "Script failed at line $1"
    log_info "Check the logs above for more details"
    exit 1
}

# Set up error trap
trap 'handle_error $LINENO' ERR

# Main execution flow
main() {
    echo -e "${PURPLE}🌟 Aztec Sequencer Node Setup Script${NC}"
    echo -e "${PURPLE}======================================${NC}\n"
    
    check_root
    setup_project_directory
    handle_existing_env
    collect_configuration
    install_dependencies
    install_docker
    install_aztec_cli
    create_env_file
    setup_systemd_service
    print_summary
    
    log_success "Setup completed successfully!"
}

# Execute main function
main "$@"