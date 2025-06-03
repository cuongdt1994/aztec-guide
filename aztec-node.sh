#!/bin/bash
set -e

# Biến USER hiện tại
USER=$(whoami)

echo "Step 1: Install Docker"
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh

# Thêm user vào group docker để không cần sudo khi chạy docker
sudo usermod -aG docker $USER

echo "Step 2: Setup aztec directory and download bin"
mkdir -p /home/$USER/.aztec
echo "Downloading aztec bin..."
curl -sL https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/bin.tar.gz -o /home/$USER/.aztec/bin.tar.gz
tar -xzf /home/$USER/.aztec/bin.tar.gz -C /home/$USER/.aztec
rm /home/$USER/.aztec/bin.tar.gz
chmod +x /home/$USER/.aztec/bin/aztec

echo "Step 3: Create .env file with user input"

# Tự động lấy IP WAN
P2P_IP=$(curl -s https://api.ipify.org)
echo "Detected public WAN IP: $P2P_IP"

read -p "Enter ETHEREUM_HOSTS (comma separated URLs): " ETHEREUM_HOSTS
read -p "Enter L1_CONSENSUS_HOST_URLS (comma separated URLs): " L1_CONSENSUS_HOST_URLS
read -p "Enter VALIDATOR_PRIVATE_KEY: " VALIDATOR_PRIVATE_KEY
read -p "Enter COINBASE address: " COINBASE

cat > /home/$USER/.aztec/.env <<EOF
ETHEREUM_HOSTS=$ETHEREUM_HOSTS
L1_CONSENSUS_HOST_URLS=$L1_CONSENSUS_HOST_URLS
VALIDATOR_PRIVATE_KEY=$VALIDATOR_PRIVATE_KEY
COINBASE=$COINBASE
P2P_IP=$P2P_IP
EOF

echo ".env created at /home/$USER/.aztec/.env"

echo "Step 4: Create systemd service file for aztec"

sudo cat > /etc/systemd/system/aztec.service <<EOF
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

echo "Reloading systemd daemon and enabling aztec service"
sudo systemctl daemon-reload
sudo systemctl enable aztec.service
sudo systemctl start aztec.service

echo "Service started successfully."

echo
echo "IMPORTANT:"
echo "Please make sure the following TCP ports are open in your firewall and router:"
echo "- TCP 8081 (Aztec node main communication)"
echo "- TCP 40401 (P2P network port)"
echo
echo "Example on Ubuntu with UFW:"
echo "  sudo ufw allow 8081/tcp"
echo "  sudo ufw allow 40401/tcp"
echo
echo "If your server is behind a NAT router, please forward these ports to your server's IP address ($P2P_IP)."
echo
echo "Setup complete!"
echo
echo "Note: You may need to log out and log back in for Docker group changes to take effect."
echo "Or run: newgrp docker"
