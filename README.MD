# 🚀 Aztec Node & Monitor Bot Setup Guide

This repository provides automation scripts to easily install and manage an Aztec blockchain node along with a monitoring bot that reports node status via Telegram.

---

## 📦 Components

1. **Aztec Node Setup Script**
2. **Aztec Monitor Bot** (Telegram-based monitoring)
3. **Systemd Services** for automatic startup & management

---

## 🖥️ System Requirements

| Requirement | Description |
|-------------|-------------|
| **OS** | Ubuntu 20.04+ or Debian 11+ |
| **RAM** | Minimum: 16GB / Recommended: 16GB+ |
| **Storage** | Minimum: 100GB SSD |
| **Network** | Stable internet connection |
| **User Access** | Sudo privileges required |

---

## 1️⃣ Aztec Node Installation

### 🔧 Step-by-Step Instructions

```bash
# Download the setup script
wget -O aztec-node.sh "https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/aztec-node.sh"

# Make it executable
chmod +x aztec-node.sh

# Run the script with sudo
sudo ./aztec-node.sh
```

📌 During installation:
- Installs required packages and Docker
- Creates `.env` file with secure permissions
- Configures public IP for P2P
- Sets up `systemd` service to run the node

---

## 2️⃣ Aztec Monitor Bot Installation

Monitor the status of your Aztec node via Telegram.

### 📋 Prerequisites

- Telegram account
- Bot Token (from BotFather)
- Your Telegram User ID

### 🤖 Create Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Start a chat and send `/newbot`
3. Follow the prompts to name your bot and get the **Bot Token**

### 🆔 Get Your Telegram User ID

#### ✅ Option 1 (Recommended)
- Search for `@userinfobot` in Telegram
- Start the bot → It shows your **User ID**

#### 🔍 Option 2 (API method)
1. Send a message to your bot
2. Open browser and go to:  
   `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Find your User ID in the response:  
   `"from":{"id": YOUR_USER_ID}`

---

### ⚙️ Bot Installation

```bash
# Download monitor bot installer
wget https://raw.githubusercontent.com/cuongdt1994/aztec-guide/main/install_aztec_bot.sh

# Make it executable
chmod +x install_aztec_bot.sh

# Run with sudo
sudo ./install_aztec_bot.sh
```

During setup, you'll be prompted for:

- `AZTEC_BOT_TOKEN` → BotFather token
- `AZTEC_AUTHORIZED_USERS` → Comma-separated list of User IDs

---

## 🛠️ Service Management

### Aztec Bot Service (`aztecrp.service`)

| Command | Purpose |
|---------|---------|
| `sudo systemctl start aztecrp.service` | Start the bot |
| `sudo systemctl stop aztecrp.service` | Stop the bot |
| `sudo systemctl restart aztecrp.service` | Restart the bot |
| `sudo systemctl status aztecrp.service` | View current status |
| `sudo journalctl -u aztecrp.service -f` | Live view logs |

---

## ✅ Test Your Setup

1. Start the bot service:
```bash
sudo systemctl start aztecrp.service
```

2. Check service is running:
```bash
sudo systemctl status aztecrp.service
```

3. Open Telegram and send `/status` to your bot

If configured correctly, it should reply with system/node status.

---

## 🧰 Troubleshooting

| Problem | Solution |
|--------|----------|
| Bot doesn't respond | ✅ Check bot token and authorized user ID |
| Service won't start | ✅ Ensure virtualenv and Python deps are installed |
| `Forbidden` error | ✅ User ID is not authorized |
| `Module not found` | ✅ Reinstall dependencies |

Check logs for more info:
```bash
sudo journalctl -u aztecrp.service -f
```

---

## 🔐 Security Notes

- Bot runs as root to monitor system/node
- Only authorized Telegram users can interact
- Credentials stored in `/root/aztecrp/.env` (permission restricted)
- Services auto-start on system boot

---

## 📞 Support

If you face issues:

- ✅ Recheck all installation steps
- ✅ Check systemctl & journalctl logs
- ✅ Ensure valid Telegram token and ID
- ✅ Verify internet access and firewall rules

Happy Node Running 🚀