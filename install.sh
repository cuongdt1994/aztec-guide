#!/bin/bash

# Check root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with root/sudo privileges!"
   echo "Please run: sudo $0"
   exit 1
fi

echo "=== STARTING AZTECRP SERVICE INSTALLATION ==="

read -p "Press Enter to continue after you have your BOT_TOKEN and USER_ID..."

# 1. Create /root/aztecrp directory
echo "1. Creating /root/aztecrp directory..."
mkdir -p /root/aztecrp
cd /root/aztecrp

# 2. Get user input
echo "2. Configuring bot information..."
read -p "Enter AZTEC_BOT_TOKEN: " BOT_TOKEN
read -p "Enter AZTEC_AUTHORIZED_USERS (comma separated): " AUTHORIZED_USERS

# Validate inputs
if [ -z "$BOT_TOKEN" ] || [ -z "$AUTHORIZED_USERS" ]; then
    echo "Error: BOT_TOKEN and AUTHORIZED_USERS cannot be empty!"
    exit 1
fi

# Create .env file
cat > /root/aztecrp/.env << EOF
AZTEC_BOT_TOKEN="$BOT_TOKEN"
AZTEC_AUTHORIZED_USERS="$AUTHORIZED_USERS"
AZTEC_SERVICE_NAME="aztec.service"
AZTEC_LOG_LINES="50"
EOF

echo ".env file created successfully"

# 3. Install Python and pip if not available
echo "3. Checking and installing Python..."
if ! command -v python3 &> /dev/null; then
    echo "Installing Python3..."
    apt update
    apt install -y python3 python3-pip python3-venv wget curl
else
    echo "Python3 is already installed"
fi

# Install wget if not available
if ! command -v wget &> /dev/null; then
    echo "Installing wget..."
    apt install -y wget
fi

# 4. Create virtual environment
echo "4. Creating virtual environment..."
python3 -m venv /root/aztecrp/venv

# 5. Activate virtual environment and install packages
echo "5. Installing required Python packages..."
source /root/aztecrp/venv/bin/activate

# Install packages
pip install --upgrade pip
pip install asyncio logging psutil python-dotenv python-telegram-bot aiohttp packaging

echo "Python packages installed successfully"

# 6. Download aztec_monitor_bot.py from GitHub
echo "6. Downloading aztec_monitor_bot.py from GitHub..."
GITHUB_URL="https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/aztec_monitor_bot.py"

echo "Downloading from: $GITHUB_URL"
wget -O /root/aztecrp/aztec_monitor_bot.py "$GITHUB_URL"

if [ $? -eq 0 ]; then
    echo "aztec_monitor_bot.py downloaded successfully"
else
    echo "Error downloading file from GitHub. Please check your internet connection."
    exit 1
fi

# 7. Create startbot.sh file
echo "7. Creating startbot.sh file..."
cat > /root/aztecrp/startbot.sh << 'EOF'
#!/bin/bash
cd /root/aztecrp
# Load environment variables
export PATH="/root/.aztec/bin:/root/aztecrp/venv/bin:$PATH"
export HOME="/root"
# Activate virtual environment
source /root/aztecrp/venv/bin/activate
# Start the bot
python aztec_monitor_bot.py
EOF

# Grant execute permission to startbot.sh
chmod +x /root/aztecrp/startbot.sh
echo "startbot.sh file created successfully"

# 8. Create systemd service
echo "8. Creating aztecrp.service..."
cat > /etc/systemd/system/aztecrp.service << 'EOF'
[Unit]
Description=Aztec Monitor Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/aztecrp
ExecStart=/root/aztecrp/startbot.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PATH=/root/.aztec/bin:/root/aztecrp/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

echo "aztecrp.service file created successfully"

# 9. Reload systemd and enable service
echo "9. Configuring systemd..."
systemctl daemon-reload
systemctl enable aztecrp.service

echo "=== INSTALLATION COMPLETED ==="
echo ""
echo "Directory structure created:"
echo "/root/aztecrp/"
echo "├── .env"
echo "├── aztec_monitor_bot.py"
echo "├── startbot.sh"
echo "└── venv/"
echo ""
echo "=== SERVICE MANAGEMENT COMMANDS ==="
echo "• Start service:    systemctl start aztecrp.service"
echo "• Stop service:     systemctl stop aztecrp.service"
echo "• Check status:     systemctl status aztecrp.service"
echo "• View logs:        journalctl -u aztecrp.service -f"
echo "• Restart service:  systemctl restart aztecrp.service"
echo "• Disable service:  systemctl disable aztecrp.service"
echo ""
echo "=== TESTING YOUR BOT ==="
echo "1. Start the service: systemctl start aztecrp.service"
echo "2. Check if it's running: systemctl status aztecrp.service"
echo "3. Send a message to your bot on Telegram"
echo "4. If there are issues, check logs: journalctl -u aztecrp.service -f"
echo ""
echo "Service has been enabled and will start automatically on boot."
echo "To start now, run: systemctl start aztecrp.service"
echo ""
echo "=== TROUBLESHOOTING ==="
echo "If the bot doesn't respond:"
echo "• Verify your BOT_TOKEN is correct"
echo "• Ensure your USER_ID is in AUTHORIZED_USERS"
echo "• Check service logs for errors"
echo "• Make sure the bot script was downloaded correctly"
