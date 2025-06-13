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

### Step 2: Download Script and Run Installation Aztec Monitor Bot

# Aztec Monitor Bot Installation Guide

## 📋 Prerequisites

Before running the installation script, you need to:
1. Create a Telegram Bot
2. Get your Telegram User ID
3. Have root/sudo access on your Linux server

## 🤖 Telegram Bot Creation Guide

### Step 1: Create Your Bot with BotFather

1. **Open Telegram** on your phone or computer
2. **Search for `@BotFather`** in the search bar
3. **Start conversation** by clicking "Start" button
4. **Create new bot** by sending command: `/newbot`
5. **Follow BotFather's instructions:**
   - Enter display name for your bot (e.g., "Aztec Monitor Bot")
   - Enter username for your bot (must end with "bot", e.g., "aztec_monitor_bot")
6. **Save the BOT TOKEN** - BotFather will provide a token like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`

### Step 2: Get Your Telegram User ID

**Method 1: Using @userinfobot (Recommended)**
1. Search for `@userinfobot` in Telegram
2. Start conversation and send any message
3. The bot will reply with your user information
4. Copy the "Id" number (e.g., `123456789`)

**Method 2: Using Telegram API**
1. Send a message to your newly created bot
2. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Replace `<YOUR_BOT_TOKEN>` with your actual bot token
4. Look for `"from":{"id": YOUR_USER_ID}` in the response

### Step 3: Multiple Users (Optional)
- Each user who wants to use the bot needs their own User ID
- Get User IDs using the same methods above
- Separate multiple IDs with commas: `123456789,987654321,555666777`

## 🚀 Installation

1. **Download and run the installation script:**

wget https://raw.githubusercontent.com/cuongdt1994/aztec-guide/main/install_aztec_bot.sh
chmod +x install_aztec_bot.sh
sudo ./install_aztec_bot.sh

2. **Enter your credentials when prompted:**
- `AZTEC_BOT_TOKEN`: Your bot token from BotFather
- `AZTEC_AUTHORIZED_USERS`: Your User ID(s) from @userinfobot

## 🔧 Service Management

After installation, use these commands to manage your bot:

Start the service
sudo systemctl start aztecrp.service

Stop the service
sudo systemctl stop aztecrp.service

Check service status
sudo systemctl status aztecrp.service

View real-time logs
sudo journalctl -u aztecrp.service -f

Restart the service
sudo systemctl restart aztecrp.service

Disable auto-start on boot
sudo systemctl disable aztecrp.service

## 🧪 Testing Your Bot

1. **Start the service:**

sudo systemctl start aztecrp.service

2. **Check if running:**

sudo systemctl status aztecrp.service


3. **Test in Telegram:**
- Open your bot in Telegram
- Send a command like `/status`
- Bot should respond if everything is working

## 🔍 Troubleshooting

### Bot doesn't respond?
- ✅ Verify BOT_TOKEN is correct
- ✅ Ensure your User ID is in AUTHORIZED_USERS
- ✅ Check service logs: `sudo journalctl -u aztecrp.service -f`
- ✅ Confirm bot script downloaded correctly

### Service won't start?
- ✅ Check Python virtual environment is created
- ✅ Verify all dependencies are installed
- ✅ Ensure proper file permissions
- ✅ Check system logs for errors

### Common Issues:
- **"Unauthorized"**: Wrong BOT_TOKEN
- **"Forbidden"**: User ID not in AUTHORIZED_USERS
- **"Connection Error"**: Network/firewall issues
- **"Module not found"**: Python dependencies missing

## 📁 File Structure

After installation, you'll have:

/root/aztecrp/
├── .env # Environment variables
├── aztec_monitor_bot.py # Main bot script
├── startbot.sh # Startup script
└── venv/ # Python virtual environment

## 🔒 Security Notes

- Bot runs as root user (required for system monitoring)
- Only authorized users can interact with the bot
- Bot token and user IDs are stored in `/root/aztecrp/.env`
- Service auto-starts on system boot

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review service logs for error messages
3. Ensure all prerequisites are met
4. Verify network connectivity and permissions
