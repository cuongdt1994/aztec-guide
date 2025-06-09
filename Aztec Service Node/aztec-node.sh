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
    local install_dir="aztec-sequencer"
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
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^#.*$ ]] && continue  # Skip comments
            [[ -z "$value" ]] && { env_valid=false; break; }
        done < "$ENV_FILE"
        
        if [ "$env_valid" = true ]; then
            export $(grep -v '^#' "$ENV_FILE" | xargs)
            
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
        unset ETHEREUM_HOSTS L1_CONSENSUS_HOST_URLS VALIDATOR_PRIVATE_KEY VALIDATOR_ADDRESS P2P_IP
    fi
}

# Collect configuration from user
collect_configuration() {
    log_step "Collecting node configuration"
    
    echo -e "${CYAN}📝 Please provide the following information:${NC}"
    
    if [ -z "$ETHEREUM_HOSTS" ]; then
        read -p "🔗 Ethereum RPC URL (e.g., https://sepolia.infura.io/v3/YOUR_KEY): " ETHEREUM_HOSTS
    fi
    
    if [ -z "$L1_CONSENSUS_HOST_URLS" ]; then
        read -p "🔗 Beacon Chain RPC URL (e.g., https://beacon-sepolia.infura.io): " L1_CONSENSUS_HOST_URLS
    fi
    
    if [ -z "$VALIDATOR_PRIVATE_KEY" ]; then
        echo -e "${YELLOW}⚠️  Keep your private key secure!${NC}"
        read -s -p "🔑 Validator Private Key (0x...): " VALIDATOR_PRIVATE_KEY
        echo
    fi
    
    if [ -z "$VALIDATOR_ADDRESS" ]; then
        read -p "🏦 Validator Ethereum Address (0x...): " VALIDATOR_ADDRESS
    fi
    
    if [ -z "$P2P_IP" ]; then
        log_info "Detecting public IP address..."
        P2P_IP=$(curl -s --max-time 10 ipv4.icanhazip.com || curl -s --max-time 10 ifconfig.me || echo "")
        
        if [ -z "$P2P_IP" ]; then
            read -p "🌐 Enter your public IP address: " P2P_IP
        else
            log_success "Detected public IP: $P2P_IP"
        fi
    fi
    
    # Validate inputs
    validate_configuration
}

# Validate configuration inputs
validate_configuration() {
    local errors=0
    
    if [[ ! "$ETHEREUM_HOSTS" =~ ^https?:// ]]; then
        log_error "Invalid Ethereum RPC URL format"
        ((errors++))
    fi
    
    if [[ ! "$L1_CONSENSUS_HOST_URLS" =~ ^https?:// ]]; then
        log_error "Invalid Beacon RPC URL format"
        ((errors++))
    fi
    
    if [[ ! "$VALIDATOR_PRIVATE_KEY" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        log_error "Invalid private key format (must be 0x followed by 64 hex characters)"
        ((errors++))
    fi
    
    if [[ ! "$VALIDATOR_ADDRESS" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        log_error "Invalid Ethereum address format"
        ((errors++))
    fi
    
    if [[ ! "$P2P_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address format"
        ((errors++))
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
    
    apt update && apt upgrade -y
    
    local packages=(
        curl iptables build-essential git wget lz4 jq make gcc nano
        automake autoconf tmux htop nvme-cli libgbm1 pkg-config
        libssl-dev libleveldb-dev tar clang bsdmainutils ncdu unzip
        ca-certificates gnupg software-properties-common apt-transport-https
    )
    
    apt install -y "${packages[@]}"
    log_success "System dependencies installed"
}

# Install Docker
install_docker() {
    log_step "Setting up Docker"
    
    if command -v docker &> /dev/null; then
        log_info "Docker already installed, checking version..."
        docker --version
        return 0
    fi
    
    # Remove old Docker packages
    local old_packages=(docker.io docker-doc docker-compose podman-docker containerd runc)
    for pkg in "${old_packages[@]}"; do
        apt-get remove -y "$pkg" 2>/dev/null || true
    done
    
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Test Docker installation
    if docker run hello-world &>/dev/null; then
        log_success "Docker installed and tested successfully"
    else
        log_error "Docker installation test failed"
        exit 1
    fi
    
    # Enable and start Docker service
    systemctl enable docker
    systemctl restart docker
}

# Install Aztec CLI
install_aztec_cli() {
    log_step "Setting up Aztec CLI"
    
    if command -v aztec &> /dev/null; then
        log_info "Aztec CLI found, updating to latest version..."
        /root/.aztec/bin/aztec-up alpha-testnet || aztec-up alpha-testnet
    else
        log_info "Installing Aztec CLI..."
        bash -i <(curl -s https://install.aztec.network)
    fi
    
    # Add to PATH
    echo 'export PATH="$PATH:/root/.aztec/bin"' >> ~/.bashrc
    export PATH="$PATH:/root/.aztec/bin"
    
    log_success "Aztec CLI setup completed"
}

# Create environment file
create_env_file() {
    log_step "Creating environment configuration"
    
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
    echo -e "${CYAN}🛠️  Would you like to set up Aztec as a systemd service?${NC}"
    echo "   This will allow automatic startup and better process management."
    read -p "Setup systemd service? [Y/n]: " SETUP_SYSTEMD
    
    if [[ ! "$SETUP_SYSTEMD" =~ ^[Nn]$ ]]; then
        log_step "Creating systemd service"
        
        cat > /etc/systemd/system/aztec-sequencer.service << EOF
[Unit]
Description=Aztec Sequencer Node
Documentation=https://docs.aztec.network/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_PATH
EnvironmentFile=$ENV_FILE
Environment=HOME=/root
Environment=PATH=/root/.aztec/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PROJECT_PATH

[Install]
WantedBy=multi-user.target
EOF
        
        # Reload and enable service
        systemctl daemon-reload
        systemctl enable aztec-sequencer
        
        echo -e "${CYAN}🚀 Start the service now? [Y/n]: ${NC}"
        read -p "" START_NOW
        
        if [[ ! "$START_NOW" =~ ^[Nn]$ ]]; then
            systemctl start aztec-sequencer
            log_success "Aztec sequencer service started"
            
            # Show service status
            echo -e "\n${CYAN}📊 Service Status:${NC}"
            systemctl status aztec-sequencer --no-pager -l
        else
            log_info "Service created but not started. Use 'systemctl start aztec-sequencer' to start."
        fi
        
        print_service_commands
    else
        print_manual_commands
    fi
}

# Print service management commands
print_service_commands() {
    echo -e "\n${CYAN}🔧 Service Management Commands:${NC}"
    echo "   • Start service:    systemctl start aztec-sequencer"
    echo "   • Stop service:     systemctl stop aztec-sequencer"
    echo "   • Restart service:  systemctl restart aztec-sequencer"
    echo "   • Check status:     systemctl status aztec-sequencer"
    echo "   • View logs:        journalctl -u aztec-sequencer -f"
    echo "   • Disable service:  systemctl disable aztec-sequencer"
}

# Print manual run commands
print_manual_commands() {
    echo -e "\n${CYAN}🚀 Manual Run Command:${NC}"
    echo "cd $PROJECT_PATH && source .env"
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
    echo "   • Project Path: $PROJECT_PATH"
    echo "   • Environment File: $ENV_FILE"
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
}

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
