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

### Step 1: Download Script and Run Installation

# Download script

wget -O aztec-node.sh "https://raw.githubusercontent.com/cuongdt1994/aztec-guide/main/Aztec%20Service%20Node/aztec-node.sh"

# Approve Permissions

chmod +x aztec-node.sh

# Running with permissions root

sudo ./aztec-node.sh
