# Aztec Node Setup Script

A comprehensive automation script for installing and configuring Aztec blockchain node on Ubuntu with systemctl support and environment variables management.

## 🚀 Features

- **Automated Installation**: System updates and all required dependencies installation
- **Docker Integration**: Docker CE installation with optimized configuration
- **Environment Management**: Secure .env file configuration with high security
- **Systemd Service**: Integrated systemctl for automatic service management
- **Interactive Setup**: User-friendly input interface with validation
- **Security First**: Hidden private key input and restricted .env file permissions
- **Auto IP Detection**: Automatic public IP detection for P2P networking

## 📋 System Requirements

- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: Minimum 4GB, recommended 8GB+
- **Storage**: Minimum 100GB SSD
- **Network**: Stable internet connection
- **User**: Account with sudo privileges (do not run as root)

## 🛠️ Quick Installation

### Step 1: Download Script

wget https://raw.githubusercontent.com/your-repo/aztec-setup/main/aztec-setup.sh
chmod +x aztec-setup.sh

### Step 2: Run Installation

./aztec-setup.sh

### Step 3: Configure Service

sudo systemctl enable aztec-node
sudo systemctl start aztec-node