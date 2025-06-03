#!/bin/bash
set -e

# Get current user
USER=$(whoami)

echo "Step 1: Checking Docker installation"
if command -v docker &> /dev/null; then
    echo "Docker is already installed. Skipping installation."
else
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    echo "Docker installed successfully."
fi

echo "Step 2: Setting up Docker permissions"
# Add user to docker group and apply changes
sudo usermod -aG docker $USER
echo "User added to docker group. Applying group changes..."
newgrp docker

echo "Step 3: Setting up Aztec directory and downloading binaries"
mkdir -p /home/$USER/.aztec
if [ -f "/home/$USER/.aztec/bin/aztec" ]; then
    echo "Aztec binary already exists. Skipping download."
else
    echo "Downloading Aztec binaries..."
    curl -sL https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/bin.tar.gz -o /home/$USER/.aztec/bin.tar.gz
    tar -xzf /home/$USER/.aztec/bin.tar.gz -C /home/$USER/.aztec
    rm /home/$USER/.aztec/bin.tar.gz
    chmod +x /home/$USER/.aztec/bin/aztec
    echo "Aztec binaries downloaded successfully."
fi

echo "Step 4: Creating environment configuration"
# Auto-detect public IP
P2P_IP=$(curl -s https://api.ipify.org)
echo "Detected public IP: $P2P_IP"

read -p "Enter ETHEREUM_HOSTS (comma-separated URLs): " ETHEREUM_HOSTS
read -p "Enter L1_CONSENSUS_HOST_URLS (comma-separated URLs): " L1_CONSENSUS_HOST_URLS
read -p "Enter VALIDATOR_PRIVATE_KEY: " VALIDATOR_PRIVATE_KEY
read -p "Enter COINBASE address: " COINBASE

cat > /home/$USER/.aztec/.env <<EOF
ETHEREUM_HOSTS=$ETHEREUM_HOSTS
L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS
VALIDATOR_PRIVATE_KEY=$VALIDATOR_PRIVATE_KEY
COINBASE=$COINBASE
P2P_IP=$P2P_IP
EOF

echo "Environment file created at /home/$USER/.aztec/.env"

echo "Step 5: Creating systemd service"
# Check if service exists and stop/remove it
if systemctl list-units --full -all | grep -Fq "aztec.service"; then
    echo "Existing Aztec service found. Stopping and removing..."
    sudo systemctl stop aztec.service 2>/dev/null || true
    sudo systemctl disable aztec.service 2>/dev/null || true
fi

# Create the service file using a temporary file approach
sudo tee /etc/systemd/system/aztec.service > /dev/null <<EOF
[Unit]
Description=Aztec Validator Node
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/.aztec
EnvironmentFile=/home/$USER/.aztec/.env
ExecStart=/home/$USER/.aztec/bin/aztec start --node --archiver --sequencer \\
  --network alpha-testnet \\
  --l1-rpc-urls \${ETHEREUM_HOSTS} \\
  --l1-consensus-host-urls \${L1_CONSENSUS_HOST_URLS} \\
  --sequencer.validatorPrivateKey \${VALIDATOR_PRIVATE_KEY} \\
  --sequencer.coinbase \${COINBASE} \\
  --p2p.p2pIp \${P2P_IP} \\
  --p2p.p2pPort 40401 \\
  --port 8081
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Configuring and starting service"
sudo systemctl daemon-reload
sudo systemctl enable aztec.service
sudo systemctl start aztec.service

echo "Service started successfully."
echo
echo "IMPORTANT - Firewall Configuration Required:"
echo "Open these TCP ports in your firewall and router:"
echo "• Port 8081 (Aztec node communication)"
echo "• Port 40401 (P2P network)"
echo
echo "Ubuntu/UFW example:"
echo "  sudo ufw allow 8081/tcp"
echo "  sudo ufw allow 40401/tcp"
echo
echo "If behind NAT, forward these ports to: $P2P_IP"
echo
echo "Setup complete!"
echo
echo "Note: If this is a fresh Docker installation, you may need to log out and back in"
echo "for the docker group changes to take full effect in new shell sessions."
