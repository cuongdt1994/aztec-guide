#!/usr/bin/env python3
# Aztec Node Monitor Bot for Telegram - Enhanced Version
# Monitors Aztec validator node service with ANSI color code support
import asyncio
import logging
import os
import subprocess
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import psutil
from contextlib import contextmanager
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
import shlex
import aiohttp
import shutil
from typing import Dict, Any
from packaging.version import parse as parse_version

load_dotenv()  # Load environment variables from .env file
# Version information
__version__ = "0.0.2"
# Configuration
BOT_TOKEN = os.getenv("AZTEC_BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("AZTEC_BOT_TOKEN environment variable not set. Please set it in .env or as an environment variable.")

AUTHORIZED_USERS = [int(uid) for uid in os.getenv("AZTEC_AUTHORIZED_USERS", "").split(",") if uid]
if not AUTHORIZED_USERS:
    raise ValueError("AZTEC_AUTHORIZED_USERS environment variable not set or empty. Please specify at least one authorized user ID.")

SERVICE_NAME = os.getenv("AZTEC_SERVICE_NAME", "aztec.service")
LOG_LINES = int(os.getenv("AZTEC_LOG_LINES", 50))
LOG_FILE = os.path.join(os.path.expanduser("~"), "aztec_monitor.log")

# Logging setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

def parse_timestamp(timestamp_str: str) -> str:
    if not timestamp_str:
        return "Unknown"
    try:
        if timestamp_str.endswith("Z"):
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(timestamp_str)
        return dt.strftime("%d-%m-%Y - %H:%M")
    except (ValueError, TypeError) as e:
        logger.debug(f"Error parsing timestamp {timestamp_str}: {e}")
        return timestamp_str[:19] if len(timestamp_str) >= 19 else timestamp_str

class AztecMonitor:

    def __init__(self):
        self.service_name = SERVICE_NAME
        self.is_windows = os.name == "nt"
        self.last_alert_time = {}  # Lưu thời gian alert cuối
        self.alert_cooldown = 1800  # 30 phút cooldown
        self.monitoring_active = False
        self.monitor_thread = None
        self.current_version = __version__
        self.remote_version_url="https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/version.json"
        self.remote_file_url="https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/aztec_monitor_bot.py"
    async def check_miss_rate_alert(self) -> Optional[Dict[str, Any]]:
        """Kiểm tra miss rate và gửi cảnh báo nếu cần"""
        try:
            # Lấy validator status
            validator_status = await self.get_validator_status()
            if not validator_status["success"] or not validator_status["validator_found"]:
                return None
            validator_data = validator_status["validator_data"]
            total_success = validator_data.get("totalAttestationsSucceeded", 0)
            total_missed = validator_data.get("totalAttestationsMissed", 0)
            success_total = total_success + total_missed
            if success_total == 0:
                return None
            miss_rate = (total_missed / success_total * 100)
            if miss_rate > 30:
                alert_key = "miss_rate_alert"
                current_time = time.time()
                # Kiểm tra cooldown
                if (alert_key not in self.last_alert_time or 
                    current_time - self.last_alert_time[alert_key] > self.alert_cooldown):
                    self.last_alert_time[alert_key] = current_time
                    
                    return {
                        "alert": True,
                        "miss_rate": miss_rate,
                        "total_attestations": success_total,
                        "missed_attestations": total_missed,
                        "validator_data": validator_data
                    }
            
            return {"alert": False, "miss_rate": miss_rate}
        except Exception as e:
            logger.error(f"Error checking miss rate: {e}")
            return None
    async def send_miss_rate_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Gửi cảnh báo miss rate qua Telegram"""
        try:
            validator_data = alert_data["validator_data"]
            miss_rate = alert_data["miss_rate"]
            total_attestations = alert_data["total_attestations"]
            missed_attestations = alert_data["missed_attestations"]
            
            # Format thông tin validator
            validator_index = validator_data.get("index", "Unknown")
            validator_address = validator_data.get("address", "Unknown")
            
            alert_message = f"""🚨 **VALIDATOR ALERT** 🚨

❌ **High Miss Rate Detected!**

📊 **Miss Rate:** {miss_rate:.1f}% (> 30%)
🎯 **Validator Index:** {validator_index}
🔗 **Address:** {validator_address[:10]}...{validator_address[-8:]}

📈 **Attestation Stats:**
• Total: {total_attestations}
• Missed: {missed_attestations}
• Success: {total_attestations - missed_attestations}

⚠️ **Action Required:**
• Check node connectivity
• Verify synchronization status
• Review system resources
• Check network latency

⏰ **Time:** {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"""

            # Gửi qua tất cả authorized users
            success_count = 0
            for user_id in AUTHORIZED_USERS:
                try:
                    escaped_message = escape_markdown_v2(alert_message)
                    
                    # Tạo application instance tạm thời để gửi message
                    temp_app = Application.builder().token(BOT_TOKEN).build()
                    await temp_app.bot.send_message(
                        chat_id=user_id,
                        text=escaped_message,
                        parse_mode="MarkdownV2"
                    )
                    success_count += 1
                    logger.info(f"Alert sent to user {user_id}")
                    
                except Exception as e:
                    logger.error(f"Failed to send alert to user {user_id}: {e}")
                    # Fallback to plain text
                    try:
                        plain_message = alert_message.replace("*", "").replace("`", "")
                        await temp_app.bot.send_message(
                            chat_id=user_id,
                            text=plain_message
                        )
                        success_count += 1
                    except Exception as e2:
                        logger.error(f"Failed to send plain text alert to user {user_id}: {e2}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending miss rate alert: {e}")
            return False
    def start_monitoring(self, check_interval: int = 300):
        """Bắt đầu monitoring tự động (mặc định 5 phút)"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
            
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(check_interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started automatic monitoring with {check_interval}s interval")

    def stop_monitoring(self):
        """Dừng monitoring tự động"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        logger.info("Stopped automatic monitoring")

    def _monitor_loop(self, check_interval: int):
        """Loop monitoring chạy trong background thread"""
        import asyncio
        
        async def monitor_task():
            while self.monitoring_active:
                try:
                    # Kiểm tra miss rate
                    alert_result = await self.check_miss_rate_alert()
                    
                    if alert_result and alert_result.get("alert"):
                        logger.warning(f"High miss rate detected: {alert_result['miss_rate']:.1f}%")
                        success = await self.send_miss_rate_alert(alert_result)
                        if success:
                            logger.info("Miss rate alert sent successfully")
                        else:
                            logger.error("Failed to send miss rate alert")
                    
                    # Chờ interval tiếp theo
                    await asyncio.sleep(check_interval)
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    await asyncio.sleep(60)  # Chờ 1 phút trước khi thử lại
        
        # Chạy async task trong thread
        try:
            asyncio.run(monitor_task())
        except Exception as e:
            logger.error(f"Monitor loop crashed: {e}")                        
    def check_authorization(self, user_id: int) -> bool:
        """Check if user is authorized"""
        return user_id in AUTHORIZED_USERS

    async def run_command(self, command: str) -> Tuple[bool, str]:
        try:
            logger.debug(f"Executing command: {command}")
            process = await asyncio.create_subprocess_exec(
                *shlex.split(command),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            stdout_decoded = stdout.decode(errors='replace').strip()
            stderr_decoded = stderr.decode(errors='replace').strip()
            
            full_output = stdout_decoded
            if stderr_decoded:
                full_output = f"{full_output}\n{stderr_decoded}" if full_output else stderr_decoded
            return process.returncode == 0, full_output
        except Exception as e:
            logger.error(f"❌ Command execution failed: {e}")
        return False, str(e)
    async def get_remote_version(self) -> Optional[str]:
        """Get remote version"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.remote_version_url) as response:
                    if response.status == 200:
                        version_text = await response.text()
                        # Parse version from the text
                        version_match = re.search(r'(\d+\.\d+\.\d+)', version_text.strip())
                        if version_match:
                            return version_match.group(1)
                        return version_text.strip()
                    return None
        except Exception as e:
            logger.error(f"Error getting remote version: {e}")
            return None
    async def get_remote_version_from_code(self) -> Optional[str]:
        """Get remote version from code"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.remote_file_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                        if version_match:
                            return version_match.group(1)
                    return None
        except Exception as e:
            logger.error(f"Error getting version from remote code: {e}")
            return None

    async def check_for_updates(self) -> bool:
        """Check for auto-update"""
        try:
            remote_version = await self.get_remote_version()
            if not remote_version:
                remote_version = await self.get_remote_version_from_code()
            if not remote_version:
                return {"error": "Could not fetch remote version"}
            logger.info(f"Current version: {self.current_version}")
            logger.info(f"Remote version: {remote_version}")
            current_parsed = parse_version(self.current_version)
            remote_parsed = parse_version(remote_version)
            if remote_parsed > current_parsed:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.remote_file_url) as response:
                        if response.status == 200:
                            remote_content = await response.text()
                            return {
                                "update_available": True,
                                "current_version": self.current_version,
                                "remote_version": remote_version,
                                "remote_content": remote_content,
                                "version_comparison": f"{self.current_version} -> {remote_version}"
                            }
                        else:
                            return {"error": f"Failed to fetch remote file: {response.status}"}
            else:
                return {
                    "update_available": False,
                    "current_version": self.current_version,
                    "remote_version": remote_version,
                    "message": "Already up to date"
                }
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return {"error": str(e)}                            
    async def apply_update(self, new_content: str, new_version: str) -> bool:
        """Apply update"""
        try:
            backup_path = f"{__file__}.backup.v{self.current_version}.{int(time.time())}"
            shutil.copy2(__file__, backup_path)
            logger.info(f"Created backup: {backup_path}")
            with open("aztec_monitor_bot.py", "w") as f:
                f.write(new_content)
            logger.info(f"File updated from v{self.current_version} to v{new_version}")
            reset_success, reset_output = await self.run_command("sudo systemctl reset-failed aztecrp.service")
            if reset_success:
                logger.info("Failed status reset successfully")
            await asyncio.sleep(2)
            success, output = await self.run_command("sudo systemctl restart aztecrp.service")
            if success:
                logger.info("Service restarted successfully after update")
                return True
            else:
                logger.error(f"Failed to restart service: {output}")
                return False 
        except Exception as e:
            logger.error(f"Update application failed: {e}")
            return False    
    async def get_service_status(self) -> Dict:
        """Get service status"""
        success, output = await self.run_command(
            f"systemctl is-active {self.service_name}"
        )
        is_active = success and output == "active"

        success, output = await self.run_command(
            f"systemctl is-enabled {self.service_name}"
        )
        is_enabled = success and output == "enabled"

        success, status_output = await self.run_command(
            f"systemctl status {self.service_name} --no-pager -l"
        )
        return {
            "active": is_active,
            "enabled": is_enabled,
            "status_output": status_output if success else "Cannot get status details",
        }

    def get_system_resources(self) -> Dict:
        """Get system resource usage"""
        return {
            "cpu": {
                "percent": psutil.cpu_percent(interval=0.1),
                "cores": psutil.cpu_count(),
            },
            "memory": {
                "total": (mem := psutil.virtual_memory()).total,
                "available": mem.available,
                "percent": mem.percent,
                "used": mem.used,
            },
            "disk": {
                "total": (disk := psutil.disk_usage("/")).total,
                "free": disk.free,
                "used": disk.used,
                "percent": (disk.used / disk.total) * 100,
            },
        }

    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Convert bytes to human-readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} PB"

    @staticmethod
    def strip_ansi_codes(text: str) -> str:
        """
        Remove ANSI escape codes from text
        Handles various ANSI sequences including colors, formatting, and cursor control
        """
        # Pattern to match ANSI escape sequences
        ansi_pattern = re.compile(
            r"\x1b\[[0-9;]*[mGKHfJABCD]|\x1b\[[0-9]+[~]|\x1b\[[0-9]*[ABCD]"
        )
        return ansi_pattern.sub("", text)

    @staticmethod
    def extract_ansi_info(text: str) -> Dict:
        """
        Extract ANSI color and formatting information from text
        Returns dict with color info and clean text
        """
        ansi_info = {
            "has_color": False,
            "colors": [],
            "formatting": [],
            "clean_text": text,
        }

        # Find all ANSI sequences
        ansi_pattern = re.compile(r"\x1b\[([0-9;]*)([mGKHfJABCD])")
        matches = ansi_pattern.findall(text)

        if matches:
            ansi_info["has_color"] = True

            for codes, command in matches:
                if command == "m":  # Color/formatting command
                    code_list = [int(c)
                                 for c in codes.split(";") if c.isdigit()]

                    for code in code_list:
                        if code == 0:
                            ansi_info["formatting"].append("reset")
                        elif code == 1:
                            ansi_info["formatting"].append("bold")
                        elif code == 22:
                            ansi_info["formatting"].append("normal_intensity")
                        elif 30 <= code <= 37:
                            ansi_info["colors"].append(f"fg_{code - 30}")
                        elif code == 39:
                            ansi_info["colors"].append("fg_default")
                        elif 40 <= code <= 47:
                            ansi_info["colors"].append(f"bg_{code - 40}")
                        elif code == 49:
                            ansi_info["colors"].append("bg_default")

            # Clean the text
            ansi_info["clean_text"] = AztecMonitor.strip_ansi_codes(text)

        return ansi_info

    @staticmethod
    def extract_component(message: str) -> str:
        """
        Extract component name from log message
        Examples:
        - "validator Using" -> "validator"
        - "archiver Downloaded L2 block" -> "archiver"
        - "p2p-client Connected to peer" -> "p2p-client"
        """
        if not message:
            return "unknown"

        # Look for component patterns at the beginning of the message
        component_patterns = [
            r"^([a-zA-Z0-9_-]+)\s+",  # component followed by space
            r"^([a-zA-Z0-9_-]+):",  # component followed by colon
            r"^([a-zA-Z0-9_-]+)\.",  # component followed by dot
        ]

        for pattern in component_patterns:
            match = re.match(pattern, message.strip())
            if match:
                return match.group(1).lower()

        # If no specific pattern found, try to get first word
        words = message.strip().split()
        if words and len(words[0]) > 2:  # Avoid very short words
            first_word = words[0].lower()
            # Check if it looks like a component name
            if re.match(r"^[a-zA-Z0-9_-]+$", first_word):
                return first_word

        return "unknown"

    @staticmethod
    def parse_log_line(line: str) -> Dict:
        """
        Enhanced log line parser with ANSI color code support
        Supports various log formats including those with ANSI color codes:
        - [20:59:47.637] [32mINFO [39m: [36m [1mvalidator [22m [0mUsing
        - [19:29:21.921] INFO: archiver Downloaded L2 block 15424
        - 2025-06-06 19:29:21 INFO Some message
        """
        # First, extract ANSI information
        ansi_info = AztecMonitor.extract_ansi_info(line)
        clean_line = ansi_info["clean_text"]

        # Enhanced regex patterns to handle various log formats
        patterns = [
            # Pattern 1: [timestamp] LEVEL: message or [timestamp] LEVEL message
            # Handles: [20:59:47.637] INFO: validator Using
            r"^\[([^\]]+)\]\s*(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)(?:\s*:\s*|\s+)(.*)$",
            # Pattern 2: timestamp LEVEL: message or timestamp LEVEL message
            # Handles: 2025-06-06 19:29:21 INFO Some message
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)(?:\s*:\s*|\s+)(.*)$",
            # Pattern 3: LEVEL: message or LEVEL message (no timestamp)
            # Handles: INFO: Some message
            r"^(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)(?:\s*:\s*|\s+)(.*)$",
            # Pattern 4: Find level anywhere in the line (fallback)
            r".*(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL).*",
        ]

        # Try to parse the clean line
        parsed_info = None
        for i, pattern in enumerate(patterns):
            match = re.match(pattern, clean_line, re.IGNORECASE)
            if match:
                groups = match.groups()

                if i == 0 or i == 1:  # Patterns with timestamp, level, message
                    if len(groups) >= 3:
                        timestamp = groups[0]
                        level = groups[1].upper()
                        message = groups[2].strip() if groups[2] else ""

                        parsed_info = {
                            "timestamp": timestamp,
                            "level": level,
                            "message": message,
                            "component": AztecMonitor.extract_component(message),
                            "raw": line,
                            "clean_raw": clean_line,
                            "has_ansi": ansi_info["has_color"],
                            "ansi_colors": ansi_info["colors"],
                            "ansi_formatting": ansi_info["formatting"],
                        }
                        break

                elif i == 2:  # Pattern with level, message (no timestamp)
                    level = groups[0].upper()
                    message = groups[1].strip() if len(
                        groups) > 1 and groups[1] else ""

                    parsed_info = {
                        "timestamp": None,
                        "level": level,
                        "message": message,
                        "component": AztecMonitor.extract_component(message),
                        "raw": line,
                        "clean_raw": clean_line,
                        "has_ansi": ansi_info["has_color"],
                        "ansi_colors": ansi_info["colors"],
                        "ansi_formatting": ansi_info["formatting"],
                    }
                    break

                else:  # Pattern 4: level found anywhere (fallback)
                    level = groups[0].upper()

                    parsed_info = {
                        "timestamp": None,
                        "level": level,
                        "message": clean_line.strip(),
                        "component": AztecMonitor.extract_component(clean_line),
                        "raw": line,
                        "clean_raw": clean_line,
                        "has_ansi": ansi_info["has_color"],
                        "ansi_colors": ansi_info["colors"],
                        "ansi_formatting": ansi_info["formatting"],
                    }
                    break

        # If no pattern matches, return as unknown level
        if not parsed_info:
            parsed_info = {
                "timestamp": None,
                "level": "UNKNOWN",
                "message": clean_line.strip(),
                "component": AztecMonitor.extract_component(clean_line),
                "raw": line,
                "clean_raw": clean_line,
                "has_ansi": ansi_info["has_color"],
                "ansi_colors": ansi_info["colors"],
                "ansi_formatting": ansi_info["formatting"],
            }

        return parsed_info

    async def get_aztec_logs(
        self,
        lines: int = LOG_LINES,
        log_level: Optional[str] = None,
        component: Optional[str] = None,
    ) -> List[Dict]:
        """Get Aztec container logs with optional filtering by log level and component"""
        success, output = await self.run_command(
            'docker ps --filter ancestor=aztecprotocol/aztec:latest --format "{{.ID}}"'
        )

        if not success or not output:
            return [{"error": "No Aztec container found"}]

        container_ids = [
            cid.strip() for cid in output.strip().splitlines() if cid.strip()
        ]
        if not container_ids:
            return [{"error": "No Aztec container found"}]

        logs = []
        for container_id in container_ids:
            success, log_output = await self.run_command(
                f'docker logs "{container_id}" --since=5m --tail {lines}'
            )

            if not success:
                logs.append(
                    {
                        "error": f"Failed to get logs for container {container_id}: {log_output}"
                    }
                )
                continue

            if not log_output.strip():
                continue

            # Process each log line
            for line in log_output.split("\n"):
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                log_entry = self.parse_log_line(stripped_line)

                # Apply log level filter if specified
                if log_level and log_level.upper() != "ALL":
                    parsed_level = log_entry.get("level", "UNKNOWN").upper()
                    if parsed_level != log_level.upper():
                        continue

                # Apply component filter if specified
                if component and component.lower() != "all":
                    parsed_component = log_entry.get(
                        "component", "unknown").lower()
                    if parsed_component != component.lower():
                        continue

                logs.append(log_entry)

        if not logs:
            filter_info = []
            if log_level and log_level.upper() != "ALL":
                filter_info.append(f"level '{log_level}'")
            if component and component.lower() != "all":
                filter_info.append(f"component '{component}'")

            if filter_info:
                return [
                    {
                        "error": f"No logs matching filter {' and '.join(filter_info)} found"
                    }
                ]
            else:
                return [{"error": "No logs found for any Aztec containers"}]

        return logs

    async def get_local_peer_id(self) -> Optional[str]:
        """
        Lấy peer ID của container Aztec từ logs Docker.
        Trả về None nếu không tìm thấy hoặc lỗi.
        """
        try:
            # Lấy container ID của Aztec container
            success, output = await self.run_command(
                'docker ps --filter ancestor=aztecprotocol/aztec:latest --format "{{.ID}}"'
            )
            if not success or not output.strip():
                logger.error("No Aztec container found")
                return None

            container_ids = [
                cid.strip() for cid in output.strip().splitlines() if cid.strip()
            ]
            if not container_ids:
                logger.error("No container IDs found after parsing output")
                return None

            container_id = container_ids[0]
            logger.debug(f"Using container ID: {container_id}")
            
            success, grep_output = await self.run_command(
                f'bash -c "docker logs {container_id} 2>&1 | grep -i peerId | head -n 1"'
            )
            #logger.debug(f"run_command success: {success}")
            #logger.debug(f"Grep raw output: {repr(grep_output)}")
            if grep_output is None or grep_output.strip() == "":
                logger.error("Container logs empty")
                return None
            #print("GREP_OUTPUT >>>", grep_output)
            #logger.debug(f"Grep output: {grep_output}")
            patterns = [
                r'"peerId":"([^"]+)"',  # JSON format: "peerId":"16Uiu2HAmUgsYNNRyMogvkmrp4rhe8dhiPCi6m5mKgtGPxKzf8FJn"
                r'peerId.*?([a-zA-Z0-9]{30,})',   # Alternative peer_id format
            ]
            for pattern in patterns:
                matches = re.findall(pattern, grep_output, re.IGNORECASE)
                if matches:
                    peer_id = matches[0].strip()
                    logger.info(f"Found local peer ID: {peer_id}")
                    return peer_id
        
            logger.warning("Could not extract peer ID from grep output")
            logger.debug(f"Grep output: {grep_output}")
            return None
        except Exception as e:
            logger.error(f"Error getting local peer ID: {e}")
            return None                                
    # Trong class AztecMonitor, thêm method này:
    async def get_peer_status(self) -> Dict[str, Any]:
        """Get comprehensive peer status information"""
        result = {
            "success": False,
            "message": "",
            "peer_found": False,
            "local_peer_id": None,
            "peer_data": None,
        }

        try:
            # Step 1: Get local peer ID
            result["local_peer_id"] = await self.get_local_peer_id()

            if not result["local_peer_id"]:
                result[
                    "message"
                ] = """❌ Could not retrieve local peer ID

    Possible causes:
    - Container not running
    - No peerId in logs yet
    - Container logs not accessible

    Try restarting the service or check container status."""
                return result

            # Step 2: Fetch network peers
            network_data = await self.fetch_network_peers()

            if not network_data:
                result[
                    "message"
                ] = f"""⚠️ Network API Error

    🆔 Local Peer ID: {result['local_peer_id'][:16]}...
    ❌ Could not fetch peer data from Aztec network API

    This might be temporary. Your node could still be working correctly."""
                return result

            peers = network_data.get("peers", [])
            if not peers:
                result[
                    "message"
                ] = f"""⚠️ No Network Peers Found

    🆔 Local Peer ID: {result['local_peer_id'][:16]}...
    📊 Network returned empty peer list

    This might indicate network issues or API problems."""
                return result

        # Step 3: Find our peer in the network (tối ưu tìm kiếm)
            local_peer = None
            for peer in peers:
                if peer.get("id") == result["local_peer_id"]:
                    local_peer = peer
                    break

            if local_peer:
                result["success"] = True
                result["peer_found"] = True
                result["peer_data"] = local_peer
                result["message"] = self.format_peer_info(local_peer)
            else:
                result["success"] = True
                result["peer_found"] = False
                result[
                    "message"
                ] = f"""❌ Peer Status: NOT FOUND

    🆔 Local Peer ID: {result['local_peer_id'][:16]}...{result['local_peer_id'][-8:]}
    ⚠️ Your peer is not visible in the Aztec network
    📊 Total network peers: {len(peers)}

    Possible reasons:
    - Node recently started (discovery takes time)
    - Network connectivity issues
    - Firewall blocking P2P connections
    - Node not fully synchronized yet

    Wait a few minutes and try again."""

            return result

        except Exception as e:
            logger.error(f"Error in get_peer_status: {e}")
            result["message"] = f"❌ Unexpected error checking peer status: {str(e)}"
            return result
    async def fetch_network_peers(self) -> Optional[Dict[str, Any]]:
        """Fetch peer data from Aztec network API"""

        try:
            url = "https://aztec.nethermind.io/api/peers?page_size=20000&latest=true"

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        peers_count = len(data.get("peers", []))
                        logger.info(
                            f"Fetched {peers_count} peers from network")
                        return data
                    else:
                        logger.error(f"API request failed with status: {response.status}")
                        response_text = await response.text()
                        logger.debug(f"Response: {response_text[:200]}")
                        return None


        except aiohttp.ClientError as e:
                logger.error(f"Network error fetching peers: {e}")
                return None
        except Exception as e:
                logger.error(f"Unexpected error fetching network peers: {e}")
                return None
    def format_peer_info(self, peer_data: Dict[str, Any]) -> str:
        """Format peer information for display"""
        try:
            peer_id = peer_data.get("id", "Unknown")
            created_at = peer_data.get("created_at", "")
            last_seen = peer_data.get("last_seen", "")
            client = peer_data.get("client", "Unknown")
            created_date = parse_timestamp(created_at)
            last_seen_date = parse_timestamp(last_seen)
            location_info = "Location not available"
            try:
                multi_addresses = peer_data.get("multi_addresses", [])
                if multi_addresses and isinstance(multi_addresses, list) and len(multi_addresses) > 0:
                    ip_info = multi_addresses[0].get("ip_info", [])
                    if ip_info and isinstance(ip_info, list) and len(ip_info) > 0:
                        geo_data = ip_info[0]
                        city = geo_data.get("city_name", "").strip()
                        country = geo_data.get("country_name", "").strip()
                        latitude = geo_data.get("latitude", "")
                        longitude = geo_data.get("longitude", "")
                        location_parts = []
                        if city:
                            location_parts.append(city)
                        if country:
                            location_parts.append(country)
                        if location_parts:
                            location_info = ", ".join(location_parts)
                        if latitude and longitude:
                            location_info += f"\n📍 Lat: {latitude}, Lng: {longitude}"
            except Exception as e:
                logger.debug(f"Error parsing location info: {e}")
                location_info = "Location parsing error"
            peer_info = f"""
🌐 Peer Status: CONNECTED ✅
📍 Location: {location_info}
🆔 Peer ID: {peer_id}
🤖 Client: {client}
⏰ First seen: {created_date}
👁️ Last seen: {last_seen_date}"""
            return peer_info
        except Exception as e:
            logger.error(f"Error formatting peer info: {e}")
            return f"❌ Error formatting peer data: {str(e)}"
    async def get_validator_owner_address(self) -> Optional[str]:
        """
        Lấy validator owner address từ container logs
        Tìm kiếm pattern: "with owner 0xA2D15ff91f1B4B9C461f92432d2541c6bbCC5c8b"
        """
        try:
            # Lấy container ID của Aztec container
            success, output = await self.run_command(
                'docker ps --filter ancestor=aztecprotocol/aztec:latest --format "{{.ID}}"'
            )
            if not success or not output.strip():
                logger.error("No Aztec container found")
                return None
            container_ids = [cid.strip() for cid in output.strip().splitlines() if cid.strip()]
            if not container_ids:
                return None
            container_id = container_ids[0]
            logger.debug(f"Using container ID: {container_id}")
            success, grep_output = await self.run_command(
                f'bash -c "docker logs {container_id} 2>&1 | grep -i owner | head -n 1"'
                )
            if not success or not grep_output.strip():
                logger.warning("No owner address found in container logs")
                return None
            pattern = r'with owner (0x[a-fA-F0-9]{40})'
            match = re.search(pattern, grep_output, re.IGNORECASE)
            if match:
                owner_address = match.group(1)
                logger.info(f"Found validator owner address: {owner_address}")
                return owner_address
            else:
                logger.warning("No owner address found in container logs")
                return None
        except Exception as e:
            logger.error(f"Error getting owner address: {e}")
            return None
    async def fetch_validator_data(self, validator_address: str) -> Optional[Dict[str, Any]]:
        """Fetch validator data from Aztec network API"""
        try:
            url = f"https://dashtec.xyz/api/validators/{validator_address.lower()}"
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    elif response.status == 404:
                        logger.warning(f"Validator not found: {validator_address}")
                        return None
                    else:    
                        logger.error(f"API request failed with status: {response.status}")
                        return None
        except aiohttp.ClientError as e:
            logger.error(f"Network error fetching validator data: {e}")
            return None
        except asyncio.TimeoutError:
            logger.error("Timeout while fetching validator data")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching validator data: {e}")
            return None
    @staticmethod        
    def get_current_epoch(base_time_str="2025-06-06T00:00:00Z", epoch_duration_sec=1152) -> int:
        """
        Tính toán số epoch hiện tại dựa trên thời gian hiện tại và thời gian cơ sở.
        """
        base_time = datetime.strptime(base_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        diff_seconds = int((now - base_time).total_seconds())
        current_epoch = diff_seconds // epoch_duration_sec
        return current_epoch

    def format_validator_info(self, validator_data: Dict[str, Any]) -> str:
        """Format validator information for display"""
        try:
            index = validator_data.get("index", "Unknown")
            address = validator_data.get("address", "Unknown")
            status = validator_data.get("status", "Unknown")
            balance = validator_data.get("balance", "0.00 STK")
            slashed = validator_data.get("slashed", False)
            total_success = validator_data.get("totalAttestationsSucceeded", 0)
            total_missed = validator_data.get("totalAttestationsMissed", 0)
            total_proposed = validator_data.get("totalBlocksProposed", 0)
            total_blockmined = validator_data.get("totalBlocksMined", 0)
            total_blockmissed= validator_data.get("totalBlocksMissed", 0)
            total_epochs = validator_data.get("totalParticipatingEpochs", 0)
            status_icon = "🟢" if status == "Active" else "🔴" if status == "Inactive" else "🟡"
            slashed_icon = "⚠️" if slashed else "✅"    
            recent_epoch_stats = validator_data.get("recentEpochStats", [])
            current_epoch = self.get_current_epoch()
            recent_3d_success = 0
            recent_3d_total = 0
            success_total = total_success + total_missed
            success_rate = (total_success / success_total * 100) if success_total > 0 else 0
            miss_rate = 100 - success_rate
            total_blocks = total_blockmined + total_proposed + total_blockmissed
            proposal_missrate = (total_blockmissed / total_blocks * 100) if total_blocks > 0 else 0
            for epoch_data in recent_epoch_stats:
                epoch_number = epoch_data.get("epochNumber")
                if epoch_number is not None and epoch_number >= current_epoch - 225:
                    success = epoch_data.get("attestationsSuccessful", 0)
                    missed = epoch_data.get("attestationsMissed", 0)
                    if success > 0 or missed > 0:
                        recent_3d_success += success
                        recent_3d_total += (success + missed)
            validator_info = f"""
🎯 Validator Status: {status} {status_icon}
🏷️ Index: {index}
💰 Balance: {balance}
{slashed_icon} Slashed: {'Yes' if slashed else 'No'}

📊 Attestations Performance:
• Total Attestations: {success_total}
• Successful: {total_success}
• Missed: {total_missed}
• Success Rate: {success_rate:.1f}%
• Missed: {miss_rate:.1f}%

📈 Epoch and Proposal Participation:
• Total Epochs: {total_epochs}
• Blocks Proposed: {total_proposed}
• Blocks Mined: {total_blockmined}
• Blocks Missed: {total_blockmissed}
• Missed: {proposal_missrate:.1f}%

🔗 Address: {address[:10]}...{address[-8:]}"""
            return validator_info
        except Exception as e:
            logger.error(f"Error formatting validator info: {e}")
            return f"❌ Error formatting validator data: {str(e)}"    
                    
    async def get_validator_status(self) -> Dict[str, Any]:
        """Get comprehensive validator status information"""
        result = {
            "success": False,
            "message": "",
            "validator_found": False,
            "owner_address": None,
            "validator_data": None,
        }
        try:
            # Step 1: Get validator owner address
            result["owner_address"] = await self.get_validator_owner_address()
            if not result["owner_address"]:
                result[
                    "message"
                ] = """❌ Could not retrieve validator owner address
    Possible causes:
    - Container not running
    - No owner address in logs yet
    - Container logs not accessible
    Try restarting the service or check container status."""
                return result
        # Step 2: Fetch validator data
            result["validator_data"] = await self.fetch_validator_data(
                result["owner_address"]
            )
            if not result["validator_data"]:
                result["message"] = f"""⚠️ Validator API Error
    🆔 Validator Owner Address: {result['owner_address'][:16]}...
    ❌ Could not fetch validator data from Aztec network API
    This might be temporary. Your node could still be working correctly."""
                return result
        # Step 3: Format validator information
            validator_data = result["validator_data"]
            result["success"] = True
            result["validator_found"] = True
            result["message"] = self.format_validator_info(validator_data)
            return result
        except Exception as e:
            logger.error(f"Error in get_validator_status: {e}")
            result["message"] = f"❌ Unexpected error checking validator status: {str(e)}"
            return result    
    async def get_sync_status(self, local_port=8080) -> dict:
        LOCAL_RPC = f"http://localhost:{local_port}"
        REMOTE_RPC = "https://aztec-rpc.cerberusnode.com"
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "node_getL2Tips",
            "params": [],
        }
        async def fetch_block_number(session, url):
            try:
                async with session.post(url, json=payload, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "result" in data and "proven" in data["result"]:
                            return int(data["result"]["proven"]["number"])
                        else:
                            logger.warning(f"Unexpected response format from {url}: {data}")
                            return None
                    else:
                        logger.warning(f"HTTP {resp.status} from {url}")
                        return None
            except asyncio.TimeoutError:
                logger.warning(f"Timeout when connecting to {url}")
                return None
            except aiohttp.ClientError as e:
                logger.warning(f"Client error for {url}: {e}")
                return None
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Data parsing error for {url}: {e}")
                return None
            except Exception as e:
                logger.warning(f"Unexpected error for {url}: {e}")
                return None
        async with aiohttp.ClientSession() as session:
            local_block_number = fetch_block_number(session, LOCAL_RPC)
            remote_block_number = fetch_block_number(session, REMOTE_RPC)
            local_block, remote_block = await asyncio.gather(local_block_number, remote_block_number)
            if local_block is not None and remote_block is not None:
                synced = local_block == remote_block
            else:
                synced = False
            result = {
                "synced": synced,
                "local": local_block,
                "remote": remote_block,
                "message": f"Local block: {local_block}\nRemote block: {remote_block}",
            }
            return result
    async def check_port_open(self, port: int, ip_address: str = None) -> Dict[str, Any]:
        """
    Kiểm tra port có mở hay không sử dụng YouGetSignal API
    """
        result = {
        "success": False,
        "port": port,
        "ip_address": ip_address,
        "is_open": False,
        "message": "",
        "response_html": ""
    }
        try:
        # Nếu không có IP, lấy IP public hiện tại
            if not ip_address:
                ip_address = await self.get_public_ip()
                if not ip_address:
                    result["message"] = "❌ Could not determine public IP address"
                    return result
            result["ip_address"] = ip_address
        # Chuẩn bị request data
            url = "https://ports.yougetsignal.com/check-port.php"
            data = {
            "remoteAddress": ip_address,
            "portNumber": str(port)
        }
            headers = {
            "Accept": "text/javascript, text/html, application/xml, text/xml, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9,vi;q=0.8,zh-CN;q=0.7,zh;q=0.6",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://www.yougetsignal.com",
            "Referer": "https://www.yougetsignal.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "X-Prototype-Version": "1.6.0",
            "X-Requested-With": "XMLHttpRequest"
        }
            async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
                async with session.post(url, data=data, headers=headers) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        result["response_html"] = html_content
                    
                        # Parse kết quả từ HTML response
                        is_open = await self.parse_port_check_response(html_content, port)
                        result["is_open"] = is_open
                        result["success"] = True
                        if is_open:
                            result["message"] = f"✅ Port {port} is OPEN on {ip_address}"
                        else:
                            result["message"] = f"❌ Port {port} is CLOSED on {ip_address}"
                    else:
                        result["message"] = f"❌ API request failed with status: {response.status}"
        except aiohttp.ClientError as e:
            logger.error(f"Network error checking port {port}: {e}")
            result["message"] = f"❌ Network error: {str(e)}"
        except asyncio.TimeoutError:
            logger.error(f"Timeout checking port {port}")
            result["message"] = f"❌ Timeout while checking port {port}"
        except Exception as e:
            logger.error(f"Unexpected error checking port {port}: {e}")
            result["message"] = f"❌ Unexpected error: {str(e)}"
        return result
    async def parse_port_check_response(self, html_content: str, port: int) -> bool:
        """
    Parse HTML response để xác định port có mở hay không
    """
        try:
            open_patterns = [
            rf'<img src="/img/flag_green\.gif".*?>.*?Port.*?{port}.*?is open',
            rf'Port.*?{port}.*?is open',
            r'<img src="/img/flag_green\.gif"',
            r'flag_green\.gif'
        ]
            closed_patterns = [
            rf'<img src="/img/flag_red\.gif".*?>.*?Port.*?{port}.*?is closed',
            rf'Port.*?{port}.*?is closed',
            r'<img src="/img/flag_red\.gif"',
            r'flag_red\.gif'
        ]
            html_lower = html_content.lower()
            for pattern in open_patterns:
                if re.search(pattern, html_lower, re.IGNORECASE | re.DOTALL):
                    return True
                for pattern in closed_patterns:
                    if re.search(pattern, html_lower, re.IGNORECASE | re.DOTALL):
                        return False
                    if "is open" in html_lower:
                        return True
                    if "is closed" in html_lower:
                        return False
            logger.warning(f"Could not parse port check response for port {port}")
            return False
        except Exception as e:
            logger.error(f"Error parsing port check response: {e}")
        return False
    async def get_public_ip(self) -> Optional[str]:
        """
    Lấy địa chỉ IP public hiện tại
    """
        try:
            urls = [
            "https://api.ipify.org",
            "https://ipinfo.io/ip",
            "https://checkip.amazonaws.com"
        ]
            async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        ) as session:
                for url in urls:
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                ip = (await response.text()).strip()
                                # Validate IP format
                                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                                    return ip
                    except Exception:
                        continue
            return None
        except Exception as e:
            logger.error(f"Error getting public IP: {e}")
        return None       








# Global monitor instance
monitor = AztecMonitor()
async def start_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Command để bắt đầu monitoring"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return
    
    # Lấy interval từ argument (mặc định 300s = 5 phút)
    interval = 300
    if context.args and len(context.args) > 0:
        try:
            interval = int(context.args[0])
            if interval < 60:  # Tối thiểu 1 phút
                interval = 60
        except ValueError:
            await update.message.reply_text("❌ Invalid interval. Using default 300 seconds.")
    
    monitor.start_monitoring(interval)
    
    text = f"""✅ **Monitoring Started**

🔍 **Miss Rate Alert:** > 30%
⏱️ **Check Interval:** {interval} seconds ({interval//60} minutes)
🔕 **Alert Cooldown:** 30 minutes
📱 **Notification:** Telegram

The bot will now automatically monitor your validator's miss rate and send alerts when it exceeds 30%."""
    
    escaped_text = escape_markdown_v2(text)
    await update.message.reply_text(escaped_text, parse_mode="MarkdownV2")

async def stop_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Command để dừng monitoring"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return
    
    monitor.stop_monitoring()
    
    text = "🛑 **Monitoring Stopped**\n\nAutomatic miss rate monitoring has been disabled."
    escaped_text = escape_markdown_v2(text)
    await update.message.reply_text(escaped_text, parse_mode="MarkdownV2")

async def monitor_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Command để kiểm tra trạng thái monitoring"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return
    
    status = "🟢 Active" if monitor.monitoring_active else "🔴 Inactive"
    
    text = f"""📊 **Monitoring Status**

🔍 **Status:** {status}
⚠️ **Alert Threshold:** > 30% miss rate
🔕 **Cooldown:** 30 minutes
📱 **Notifications:** Telegram

**Commands:**
• `/start_monitor [interval]` - Start monitoring
• `/stop_monitor` - Stop monitoring
• `/monitor_status` - Check status"""
    
    escaped_text = escape_markdown_v2(text)
    await update.message.reply_text(escaped_text, parse_mode="MarkdownV2")
async def handle_port_check_menu(query) -> None:
    """Handle port check menu"""
    text = """🔍 **Port Check Tool**
    Enter port number to check if it's open on your public IP address.

Common ports:
• 8080 - HTTP Alternative
• 8081 - HTTP Alternative  
• 3000 - Development Server
• 9000 - Various Services
• 22 - SSH
• 80 - HTTP
• 443 - HTTPS

Please enter a port number (1-65535):"""
    escaped_text = escape_markdown_v2(text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
        ]),
        parse_mode="MarkdownV2"
    )
async def handle_port_check_custom(update: Update, context:ContextTypes.DEFAULT_TYPE) -> None:
    """Handle custom port check input"""
    query = update.callback_query
    user_id = query.from_user.id
    if not monitor.check_authorization(user_id):
        await query.answer("❌ Unauthorized access!")
        return
    text = """🔍 **Custom Port Check**
    Enter the details in format:
`port` or `ip:port`

Examples:
• `8080` - Check port 8080 on your public IP
• `192.168.1.100:3000` - Check port 3000 on specific IP
• `example.com:80` - Check port 80 on domain

Please enter port or ip:port:"""
    escaped_text = escape_markdown_v2(text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
        ]),
        parse_mode="MarkdownV2"
    )
    context.user_data["awaiting_port_check"] = True
        



async def handle_user_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return
    if context.user_data.get("awaiting_port"):
        port_text = update.message.text.strip()
        if not port_text.isdigit():
            await update.message.reply_text("❌ Invalid port number! Please enter a valid number.")
            return
        port = int(port_text)
        context.user_data["awaiting_port"] = False
        msg = f"🔍 Checking sync status on port `{port}`..."
        escaped_msg = escape_markdown_v2(msg)
        await update.message.reply_text(escaped_msg, parse_mode="MarkdownV2")
        status = await monitor.get_sync_status(local_port=port)
        local = status["local"]
        remote = status["remote"]
        synced = status["synced"]
        if local is None or remote is None:
            text = (
                "❌ Could not fetch sync status.\n"
                f"🧱 Local block: {local or 'N/A'}\n"
                f"🌐 Remote block: {remote or 'N/A'}"
            )
        elif synced:
            text = f"✅ Node is fully synced!\n\n🧱 Local: {local}\n🌐 Remote: {remote}"
        else:
            percent = f"{(local / remote * 100):.2f}%" if local and remote else "N/A"
            text = f"⏳ Syncing...\n\n🧱 Local: {local}\n🌐 Remote: {remote}\n📈 Progress: {percent}"

        await update.message.reply_text( escape_markdown_v2(text), parse_mode="MarkdownV2")
    elif context.user_data.get("awaiting_port_check"):
        input_text = update.message.text.strip()
        context.user_data["awaiting_port_check"] = False
        try:
            # Parse input: port hoặc ip:port
            if ":" in input_text:
                parts = input_text.rsplit(":", 1)
                ip_address = parts[0]
                port = int(parts[1])
            else:
                ip_address = None
                port = int(input_text)
            if not (1 <= port <= 65535):
                await update.message.reply_text("❌ Port number must be between 1 and 65535!")
                return
            checking_msg = f"🔍 Checking port {port}"
            if ip_address:
                checking_msg += f" on {ip_address}"
            checking_msg += "...\n\n⏳ Please wait..."
            await update.message.reply_text(checking_msg)
            result = await monitor.check_port_open(port, ip_address)
            if result["success"]:
                status_icon = "🟢" if result["is_open"] else "🔴"
                status_text = "OPEN" if result["is_open"] else "CLOSED"
                text = f"""🔍 **Port Check Result**

{status_icon} **Status:** {status_text}
🌐 **IP Address:** {result['ip_address']}
🔌 **Port:** {result['port']}

{result['message']}"""
                if result["is_open"]:
                    text += f"""

✅ **Port {port} is accessible from the internet**
• Services can accept incoming connections
• Port forwarding is working correctly
• No firewall blocking this port"""
                else:
                    text += f"""

❌ **Port {port} is not accessible from the internet**

**Possible causes:**
• Port is not open/listening
• Firewall blocking the port
• Router not forwarding the port
• Service not running on this port

**To fix:**
• Check if service is running
• Configure port forwarding on router
• Allow port through firewall"""

            else:
                text = f"""🔍 **Port Check Result**

❌ **Error checking port {port}**

{result['message']}"""
            escaped_text = escape_markdown_v2(text)
            await update.message.reply_text(
                escaped_text,
                parse_mode="MarkdownV2"
            )
        except ValueError:
            await update.message.reply_text("❌ Invalid input! Please enter a valid port number or ip:port format.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error processing input: {str(e)}")    


async def handle_sync_status_custom(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    user_id = query.from_user.id
    if not monitor.check_authorization(user_id):
        await query.answer("❌ Unauthorized access!", show_alert=True)
        return
    text = "📥 Please enter the *port number* your Aztec RPC is running on (e.g. 8080, 9000):"
    escaped_text = escape_markdown_v2(text)    
    await query.edit_message_text(escaped_text, parse_mode="MarkdownV2")
    context.user_data["awaiting_port"] = True        
async def handle_validator_status(query) -> None:
        """Handle validator status check"""
        # Show loading message với progress indication
        loading_msg = """🔍 Checking validator status...
⏳ Getting validator owner address...
⏳ Fetching validator data...
Please wait..."""
        await query.edit_message_text(loading_msg, reply_markup=None)
        # Get validator status
        status = await monitor.get_validator_status()
        # Format message
        if status["success"]:
            text = f"🎯 Validator Status\n\n{status['message']}"
        else:
            text = f"🎯 Validator Status\n\n{status['message']}"
        back_button = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
                [InlineKeyboardButton("🔄 Retry", callback_data="validator_status")],
            ]
        )
        try:
            escaped_text = escape_markdown_v2(text)
            await query.edit_message_text(
                escaped_text, reply_markup=back_button, parse_mode="MarkdownV2"
            )
        except Exception as e:
            logger.warning(f"Markdown parsing failed, using plain text: {e}")
            plain_text = text.replace("*", "").replace("`", "").replace("\\", "")
            await query.edit_message_text(plain_text, reply_markup=back_button)
async def handle_peer_status(query) -> None:
    """Handle peer status check"""
    # Show loading message với progress indication
    loading_msg = """🔍 Checking peer status...

⏳ Getting local peer ID...
⏳ Fetching network data...
⏳ Comparing with network peers...

Please wait..."""

    await query.edit_message_text(loading_msg, reply_markup=None)

    # Get peer status
    status = await monitor.get_peer_status()

    # Format message
    if status["success"]:
        if status["peer_found"]:
            text = f"🌐 **Aztec Peer Status**\n\n{status['message']}"
        else:
            text = f"🌐 **Aztec Peer Status**\n\n{status['message']}"
    else:
        text = f"🌐 **Aztec Peer Status**\n\n{status['message']}"

    # Create back button
    back_button = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
            [InlineKeyboardButton("🔄 Retry", callback_data="peer_status")],
        ]
    )

    # Try with markdown first, fallback to plain text
    try:
        escaped_text = escape_markdown_v2(text)
        await query.edit_message_text(
            escaped_text, reply_markup=back_button, parse_mode="MarkdownV2"
        )
    except Exception as e:
        # Fallback to plain text
        logger.warning(f"Markdown parsing failed, using plain text: {e}")
        plain_text = text.replace("*", "").replace("`", "").replace("\\", "")
        await query.edit_message_text(plain_text, reply_markup=back_button)


def create_main_menu() -> InlineKeyboardMarkup:
    """Create main menu with port check option"""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📊 Service Status", callback_data="status"),
                InlineKeyboardButton("💻 System Resources", callback_data="resources"),
            ],
            [
                InlineKeyboardButton("🎯 Validator Status", callback_data="validator_status"),
                InlineKeyboardButton("🌐 Peer Status", callback_data="peer_status"),
            ],
            [
                InlineKeyboardButton("📦 Sync Status", callback_data="sync_custom"),
                InlineKeyboardButton("🔍 Port Check", callback_data="port_check"),
            ],
            [
                InlineKeyboardButton("🔧 Check RPC", callback_data="service_menu"),
                InlineKeyboardButton("📝 View Logs", callback_data="logs_menu"),
            ],
            [   
                InlineKeyboardButton("🔄 Refresh", callback_data="refresh"),
            ]
        ]
    )



def create_logs_menu() -> InlineKeyboardMarkup:
    """Create enhanced logs menu with component filtering"""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📄 All Logs", callback_data="logs_all"),
                InlineKeyboardButton("ℹ️ INFO", callback_data="logs_info"),
            ],
            [
                InlineKeyboardButton("⚠️ WARN", callback_data="logs_warn"),
                InlineKeyboardButton("❌ ERROR", callback_data="logs_error"),
            ],
            [
                InlineKeyboardButton("🐛 DEBUG", callback_data="logs_debug"),
                InlineKeyboardButton("💀 FATAL", callback_data="logs_fatal"),
            ],
            [
                InlineKeyboardButton("🔧 Components", callback_data="components_menu"),
                InlineKeyboardButton("🎨 Clean View", callback_data="logs_clean"),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
        ]
    )


def create_components_menu() -> InlineKeyboardMarkup:
    """Create component filtering menu"""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("✅ Validator", callback_data="comp_validator"),
                InlineKeyboardButton("📦 Archiver", callback_data="comp_archiver"),
            ],
            [
                InlineKeyboardButton("🌐 P2P Client", callback_data="comp_p2p-client"),
                InlineKeyboardButton("⛓️ Sequencer", callback_data="comp_sequencer"),
            ],
            [
                InlineKeyboardButton("🔗 Prover", callback_data="comp_prover"),
                InlineKeyboardButton("📡 Node", callback_data="comp_node"),
            ],
            [
                InlineKeyboardButton("🔄 PVX Client", callback_data="comp_pxe"),
                InlineKeyboardButton(
                    "🌐 World State", callback_data="comp_world_state"
                ),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="logs_menu")],
        ]
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return

    welcome_text = (
    "🚀 Aztec Node Monitor Bot - Enhanced\n\n"
    "Welcome to the enhanced Aztec Node monitoring bot!\n\n"
    "✨ Features:\n"
    "🎨 ANSI color code parsing\n"
    "🔧 Component-based filtering\n"
    "🎯 Enhanced log analysis\n"
    "🚨 Automatic miss rate alerts\n"
    "🌐 Real-time network peer tracking\n\n"
    "📋 Available Options:\n"
    "📊 Check service status\n"
    "💻 Monitor system resources\n"
    "🎯 Validator & peer status\n"
    "📦 Sync status monitoring\n"
    "🔍 Port connectivity check\n"
    "📝 View logs by level & component\n\n"
    "🔗 Data Sources:\n"
    "📊 Validator metrics: Dashtec.xyz\n"
    "🌐 Network peers: Nethermind.io\n"
    "🐳 Local logs: Docker containers\n\n"
    "🙏 Special Thanks:\n"
    "💝 Thank you for trusting our monitoring solution\n"
    "🌟 Your feedback helps us improve continuously\n"
    "🤝 Grateful to Dashtec.xyz & Nethermind.io for data APIs\n"
    "🚀 Thanks to the Aztec Protocol team for the amazing platform\n\n"
    "💖 We appreciate you choosing our bot!\n"
    "Hope this tool makes managing your Aztec node effortless.\n\n"
    "Select an option below:"
)



    await update.message.reply_text(
        escape_markdown_v2(welcome_text),
        reply_markup=create_main_menu(),
        parse_mode="MarkdownV2",
    )


async def button_handler(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE) -> None:
    """Enhanced button handler with component filtering"""
    query = update.callback_query
    user_id = query.from_user.id

    if not monitor.check_authorization(user_id):
        await query.answer("❌ Unauthorized access!", show_alert=True)
        return

    await query.answer()

    if query.data == "main_menu":
        await query.edit_message_text(
            "🏠 **Main Menu**\n\nSelect an option:",
            reply_markup=create_main_menu(),
            parse_mode="MarkdownV2",
        )
    elif query.data == "status":
        await handle_status(query)
    elif query.data == "resources":
        await handle_resources(query)
    elif query.data == "validator_status":
        await handle_validator_status(query)    
    elif query.data == "peer_status":
        await handle_peer_status(query)
    elif query.data == "port_check":
        await handle_port_check_custom(update, context)    
    elif query.data == "sync_custom":
        await handle_sync_status_custom(update, context)      
    elif query.data == "logs_menu":
        text = (
            "📝 Enhanced Logs Menu\n\n"
            "🎨 Clean View - Removes ANSI codes\n"
            "🔧 Components - Filter by component\n\n"
            "Select log level or filter:"
        )
        escaped_text = escape_markdown_v2(text)
        final_text = escaped_text.replace(
            "📝 Enhanced Logs Menu", "*📝 Enhanced Logs Menu*"
        )

        await query.edit_message_text(
            final_text, reply_markup=create_logs_menu(), parse_mode="MarkdownV2"
        )
    elif query.data == "components_menu":
        await query.edit_message_text(
            "🔧 **Component Filter**\n\n" "Filter logs by specific components:",
            reply_markup=create_components_menu(),
            parse_mode="MarkdownV2",
        )
    elif query.data == "service_menu":
        await query.edit_message_text(
            "🔧 **Service Management**\n\nSelect action:",
            reply_markup=create_service_menu(),
            parse_mode="MarkdownV2",
        )
    elif query.data == "refresh":
        text = "🔄 \\*\\*Refreshed\\*\\*\n\nData updated\\!"
        await query.edit_message_text(
            text, reply_markup=create_main_menu(), parse_mode="MarkdownV2"
        )
    elif query.data == "logs_clean":
        await handle_logs_enhanced(query, clean_view=True)
    elif query.data.startswith("logs_"):
        log_level = query.data.replace("logs_", "")
        await handle_logs_enhanced(query, log_level=log_level)
    elif query.data.startswith("comp_"):
        component = query.data.replace("comp_", "")
        await handle_logs_enhanced(query, component=component)
async def handle_status(query) -> None:
    """Handle service status check"""
    status = await monitor.get_service_status()
    status_icon = "🟢" if status["active"] else "🔴"
    enabled_icon = "✅" if status["enabled"] else "❌"

    # Hide sensitive information from status output
    def mask_sensitive(text):
        text = re.sub(
            r"(0x[a-fA-F0-9]{32,}|[A-Za-z0-9+/=]{32,})",
            "[HIDDEN]",
            text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b", "[IP:PORT]", text)
        return text

    safe_status_output = mask_sensitive(status["status_output"])
    details = safe_status_output[:1000] + (
        "..." if len(safe_status_output) > 1000 else ""
    )

    # Escape markdown characters
    escaped_details = escape_markdown_v2(details)

    text = (
        f"📊 *Aztec Service Status*\n\n"
        f"{status_icon} *Status:* {'Running' if status['active'] else 'Stopped'}\n"
        f"{enabled_icon} *Auto\\-start:* {'Enabled' if status['enabled'] else 'Disabled'}\n\n"
        f"*Details:*\n"
        f"```\n{escaped_details}\n```"
    )

    try:
        await query.edit_message_text(
            text,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Back", callback_data="main_menu")]]
            ),
            parse_mode="MarkdownV2",
        )
    except Exception as e:
        # Fallback to plain text
        logger.warning(f"Markdown parsing failed, using plain text: {e}")
        plain_text = text.replace("*", "").replace("`", "").replace("\\", "")
        await query.edit_message_text(
            plain_text,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Back", callback_data="main_menu")]]
            ),
        )


async def handle_resources(query) -> None:
    """Handle system resources display"""
    resources = monitor.get_system_resources()
    cpu_icon = (
        "🟢"
        if resources["cpu"]["percent"] < 70
        else "🟡" if resources["cpu"]["percent"] < 90 else "🔴"
    )
    mem_icon = (
        "🟢"
        if resources["memory"]["percent"] < 70
        else "🟡" if resources["memory"]["percent"] < 90 else "🔴"
    )
    disk_icon = (
        "🟢"
        if resources["disk"]["percent"] < 70
        else "🟡" if resources["disk"]["percent"] < 90 else "🔴"
    )

    # Format text without MarkdownV2 formatting first
    text = (
        f"💻 System Resources\n\n"
        f"{cpu_icon} CPU: {resources['cpu']['percent']:.1f}% ({resources['cpu']['cores']} cores)\n\n"
        f"{mem_icon} RAM: {resources['memory']['percent']:.1f}%\n"
        f"• Used: {monitor.format_bytes(resources['memory']['used'])}\n"
        f"• Free: {monitor.format_bytes(resources['memory']['available'])}\n"
        f"• Total: {monitor.format_bytes(resources['memory']['total'])}\n\n"
        f"{disk_icon} Disk: {resources['disk']['percent']:.1f}%\n"
        f"• Used: {monitor.format_bytes(resources['disk']['used'])}\n"
        f"• Free: {monitor.format_bytes(resources['disk']['free'])}\n"
        f"• Total: {monitor.format_bytes(resources['disk']['total'])}\n\n"
        f"⏰ Updated: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
    )

    # Now escape the entire text for MarkdownV2
    escaped_text = escape_markdown_v2(text)

    # Apply bold formatting to headers only after escaping
    final_text = escaped_text.replace(
        "💻 System Resources", "*💻 System Resources*")
    final_text = final_text.replace("CPU:", "*CPU:*")
    final_text = final_text.replace("RAM:", "*RAM:*")
    final_text = final_text.replace("Disk:", "*Disk:*")
    final_text = final_text.replace("Updated:", "*Updated:*")

    try:
        await query.edit_message_text(
            final_text,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Back", callback_data="main_menu")]]
            ),
            parse_mode="MarkdownV2",
        )
    except Exception as e:
        # Fallback to plain text
        logger.warning(f"Markdown parsing failed, using plain text: {e}")
        await query.edit_message_text(
            text,  # Use original unescaped text
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Back", callback_data="main_menu")]]
            ),
        )


def escape_markdown_v2(text: str) -> str:
    """
    Escape special characters for Telegram's MarkdownV2 format
    """
    if not text:
        return text

    # Characters that need to be escaped in MarkdownV2
    special_chars = [
        "_",
        "*",
        "[",
        "]",
        "(",
        ")",
        "~",
        "`",
        ">",
        "#",
        "+",
        "-",
        "=",
        "|",
        "{",
        "}",
        ".",
        "!",
    ]

    # Escape each character
    for char in special_chars:
        text = text.replace(char, f"\\{char}")

    return text

async def handle_logs_enhanced(
        query,
        log_level: str = None,
        component: str = None,
        clean_view: bool = False) -> None:
    """Enhanced log handler with component filtering and clean view option"""
    # Get logs from Aztec container, filter by level and component
    logs = await monitor.get_aztec_logs(
        lines=LOG_LINES,
        log_level=None if log_level == "all" else log_level,
        component=component,
    )

    if not logs or ("error" in logs[0]):
        error_msg = (logs[0].get("error", "No logs available.")
                     if logs else "No logs available.")
        # Escape the error message
        escaped_error = escape_markdown_v2(error_msg)
        text = f"❌ *Error*\n\n{escaped_error}"
    else:
        # Prepare log content for sending
        max_len = 3000
        log_lines = []
        total_length = 0

        # Add summary info
        component_counts = {}
        level_counts = {}
        ansi_count = 0

        for log in logs:
            # Count components
            comp = log.get("component", "unknown")
            component_counts[comp] = component_counts.get(comp, 0) + 1

            # Count levels
            level = log.get("level", "UNKNOWN")
            level_counts[level] = level_counts.get(level, 0) + 1

            # Count ANSI logs
            if log.get("has_ansi", False):
                ansi_count += 1

        # Format logs for display
        for log in logs:
            if clean_view:
                if log.get("timestamp"):
                    line = f"[{log['timestamp']}] {log['level']}: {log['component']} {log['message']}"
                else:
                    line = f"{
                        log['level']}: {
                        log['component']} {
                        log['message']}"
            else:
                line = log.get("clean_raw", log.get("message", ""))

            if len(line) > 200:
                line = line[:197] + "..."

            if total_length + len(line) + 1 > max_len:
                log_lines.append("...[truncated]...")
                break
            log_lines.append(line)
            total_length += len(line) + 1

        # Build title based on filters (escape after building)
        title_parts = []
        if log_level and log_level != "all":
            level_icons = {
                "info": "ℹ️",
                "warn": "⚠️",
                "error": "❌",
                "debug": "🐛",
                "fatal": "💀",
            }
            icon = level_icons.get(log_level.lower(), "📝")
            title_parts.append(f"{icon} {log_level.upper()}")

        if component and component != "all":
            title_parts.append(f"🔧 {component.upper()}")

        if clean_view:
            title_parts.append("🎨 CLEAN")

        if not title_parts:
            title_parts.append("📄 ALL")

        # Build title and summary
        title_text = f"{' + '.join(title_parts)} Logs"
        summary_text = f"Summary: {len(logs)} entries"
        if ansi_count > 0:
            summary_text += f" ({ansi_count} with colors)"

        # Add top components if filtering isn't active
        if not component and len(component_counts) > 1:
            top_components = sorted(
                component_counts.items(), key=lambda x: x[1], reverse=True
            )[:3]
            comp_text = ", ".join(
                [f"{comp}({count})" for comp, count in top_components]
            )
            summary_text += f"\nTop: {comp_text}"

        # Escape all text components
        escaped_title = escape_markdown_v2(title_text)
        escaped_summary = escape_markdown_v2(summary_text)
        log_text = "\n".join(log_lines)
        escaped_log_text = escape_markdown_v2(log_text)

        # Build final text with proper formatting
        text = f"*{escaped_title}*\n\n📊 *{escaped_summary}*\n\n```\n{escaped_log_text}\n```"

    # Determine which menu to return to
    if component:
        back_menu = create_components_menu()
    else:
        back_menu = create_logs_menu()

    try:
        await query.edit_message_text(
            text, reply_markup=back_menu, parse_mode="MarkdownV2"
        )
    except Exception as e:
        # Fallback to plain text if markdown parsing fails
        logger.warning(f"Markdown parsing failed, using plain text: {e}")
        # Remove all markdown formatting for plain text
        plain_text = text.replace("*", "").replace("`", "").replace("\\", "")
        await query.edit_message_text(plain_text, reply_markup=back_menu)

async def update_aztec_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return

    await update.message.reply_text("🔍 Checking for updates...")
    
    try:
        result = await monitor.check_for_updates()
        
        if result.get("update_available"):
            current_ver = result["current_version"]
            remote_ver = result["remote_version"]
            
            update_msg = f"""🔄 **Update Available!**

📦 **Current Version:** {current_ver}
🆕 **New Version:** {remote_ver}
🔄 **Updating...**

Please wait while the bot updates and restarts..."""
            
            await update.message.reply_text(escape_markdown_v2(update_msg), parse_mode="MarkdownV2")
            
            success = await monitor.apply_update(result["remote_content"], remote_ver)
            if success:
                final_msg = f"✅ **Update Successful!**\n\nUpdated from v{current_ver} to v{remote_ver}\nBot restarted with new version."
                await update.message.reply_text(escape_markdown_v2(final_msg), parse_mode="MarkdownV2")
            else:
                await update.message.reply_text("❌ Update failed. Check logs for details.")
        elif result.get("error"):
            await update.message.reply_text(f"❌ Error: {result['error']}")
        else:
            current_ver = result["current_version"]
            remote_ver = result["remote_version"]
            msg = f"✅ **Already Up to Date**\n\nCurrent version: {current_ver}\nRemote version: {remote_ver}"
            await update.message.reply_text(escape_markdown_v2(msg), parse_mode="MarkdownV2")
            
    except Exception as e:
        logger.error(f"Error in update_aztec_file: {e}")
        await update.message.reply_text(f"❌ Unexpected error: {str(e)}")

async def version_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command để xem thông tin version"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return
    
    try:
        remote_version = await monitor.get_remote_version()
        if not remote_version:
            remote_version = await monitor.get_remote_version_from_code()
        
        current_parsed = parse_version(__version__)
        remote_parsed = parse_version(remote_version) if remote_version else None
        
        status = "🟢 Up to date"
        if remote_parsed and remote_parsed > current_parsed:
            status = "🟡 Update available"
        elif not remote_version:
            status = "🔴 Cannot check remote"
        
        version_text = f"""📦 **Version Information**

🏷️ **Current Version:** {__version__}
🌐 **Remote Version:** {remote_version or 'Unknown'}
📊 **Status:** {status}

⏰ **Last Check:** {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

**Commands:**
• `/version` - Check version info
• `/update_aztec` - Update if available"""
        
        escaped_text = escape_markdown_v2(version_text)
        await update.message.reply_text(escaped_text, parse_mode="MarkdownV2")
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error checking version: {str(e)}")

def main():
    """Main function"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN is not configured")
        return
    if not AUTHORIZED_USERS:
        logger.error("AUTHORIZED_USERS is not configured")
        return

    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_input))
    application.add_handler(CommandHandler("start_monitor", start_monitor))
    application.add_handler(CommandHandler("stop_monitor", stop_monitor))
    application.add_handler(CommandHandler("monitor_status", monitor_status))
    application.add_handler(CommandHandler("update_aztec", update_aztec_file))
    application.add_handler(CommandHandler("version", version_info))
    logger.info("Enhanced Aztec Monitor Bot started with automatic monitoring...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()