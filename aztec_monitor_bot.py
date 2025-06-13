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
import sys
import json
from packaging.version import parse as parse_version


load_dotenv()  # Load environment variables from .env file
# Version information
__version__ = "0.0.5"
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
        self.last_alert_time = {}
        self.alert_cooldown = 1800
        self.monitoring_active = False
        self.monitor_thread = None
        self.bot_version = __version__
        self.bot_remote_version_url = "https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/version.json"
        self.remote_file_url = "https://raw.githubusercontent.com/cuongdt1994/aztec-guide/refs/heads/main/aztec_monitor_bot.py"
        self.node_docker_api = "https://hub.docker.com/v2/repositories/aztecprotocol/aztec/tags"
        self.min_node_version = "0.87.0"
        self.version_cache = {}
        self.cache_expiry = 300
        self.cache = {}

    async def get_node_current_version(self) -> Optional[str]:
        paths = [
        "/home/ubuntu/.aztec/bin/aztec",
        "/root/.aztec/bin/aztec", 
        f"{os.path.expanduser('~')}/.aztec/bin/aztec",
        "/usr/local/bin/aztec",
        "aztec"  # In PATH
    ]
        aztec_cmd = None
        for path in paths:
            if path == "aztec":
                try:
                    subprocess.run(["which", "aztec"], check=True, capture_output=True, timeout=2)
                    aztec_cmd = "aztec"
                    break
                except:
                    continue
            elif os.path.isfile(path) and os.access(path, os.X_OK):
                aztec_cmd = path
                break    
        if not aztec_cmd:
            return None
        for flag in ["-V", "--version", "-v"]:
            try:
                result = subprocess.run(
                [aztec_cmd, flag],
                capture_output=True,
                text=True,
                timeout=5
            )
                output = result.stdout + result.stderr
                match = re.search(r'(\d+\.\d+\.\d+)', output)
                if match:
                    return match.group(1)
            except:
                continue
        return None           
    async def fetch_available_versions(self, use_cache: bool = True) -> List[str]:
        current_time = time.time()
        if use_cache and 'versions' in self.version_cache:
            cache_time = self.version_cache.get('timestamp', 0)
            if current_time - cache_time < self.cache_expiry:
                logger.info("Using cached versions")
                return self.version_cache['versions']
        try:
            all_versions = []
            page = 1
            page_size = 100
            max_pages = 50
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                while page <= max_pages:
                    url = f"{self.node_docker_api}?page={page}&page_size={page_size}"
                    async with session.get(url) as response:
                        if response.status != 200:
                            logger.error(f"Docker Hub API request failed: {response.status}")
                            break
                        data = await response.json()
                        tags = data.get("results", [])
                    
                        if not tags:
                            break
                        page_versions = self._extract_valid_versions(tags)
                        all_versions.extend(page_versions)
                        if not data.get("next"):
                            break
                        page += 1
                        if len(all_versions) >= 100:
                            break
            
                all_versions.sort(key=parse_version, reverse=True)
                self.version_cache = {
                    'versions': all_versions,
                    'timestamp': current_time
                }
                logger.info(f"Found {len(all_versions)} valid versions")
                return all_versions
        except Exception as e:
            logger.error(f"Error fetching available versions: {e}")
        if 'versions' in self.version_cache:
            logger.info("Returning cached versions due to error")
            return self.version_cache['versions']
        return []

    def _extract_valid_versions(self, tags: List[Dict]) -> List[str]:
        valid_versions = []
        min_version_parsed = parse_version(self.min_node_version)
        for tag in tags:
            tag_name = tag.get("name", "")
            if any(keyword in tag_name.lower() for keyword in ['nightly', 'dev', 'beta', 'alpha', 'rc', 'latest']):
                continue
            if re.match(r'^\d+\.\d+\.\d+$', tag_name):
                try:
                    tag_version = parse_version(tag_name)
                    if tag_version >= min_version_parsed:
                        valid_versions.append(tag_name)
                except ValueError:
                    logger.debug(f"Error parsing version {tag_name}")
                    continue
        return valid_versions
                     
    async def check_node_update(self) -> Dict[str, Any]:
        result = {
            "success": False,
            "current_version": None,
            "latest_version": None,
            "update_available": False,
            "message": "",
            "available_versions": [],
            "newer_versions": []
        }
        try:
            current_version = await self.get_node_current_version()
            if not current_version:
                result["message"] = "❌ Cannot determine current node version"
                return result
            result["current_version"] = current_version       
            available_versions = await self.fetch_node_versions()
            if not available_versions:
                result["message"] = "❌ Cannot fetch available versions from Docker Hub"
                return result
            result["available_versions"] = available_versions
            result["latest_version"] = available_versions[0]
            current_parsed = parse_version(current_version)
            newer_versions = []
            for version in available_versions:
                if parse_version(version) > current_parsed:
                    newer_versions.append(version)
            result["newer_versions"] = newer_versions
            result["success"] = True
            
            if newer_versions:
                result["update_available"] = True
                result["message"] = f"""🔄 Node Update Available!

📦 Current Version: {current_version}
🆕 Latest Version: {result['latest_version']}
📊 Status: {len(newer_versions)} newer version(s) available

🔝 Recent versions: {', '.join(newer_versions[:5])}{'...' if len(newer_versions) > 5 else ''}

⚡ Quick update to latest: aztec-up -v {result['latest_version']}"""
            else:
                result["message"] = f"""✅ Node Up to Date

📦 Current Version: {current_version}
🌐 Latest Version: {result['latest_version']}
📊 Status: No update needed

Your node is running the latest stable version."""
            
            return result            
        except Exception as e:
            logger.error(f"Error checking node update: {e}")
            result["message"] = f"❌ Error checking node update: {str(e)}"
            return result
    async def fetch_node_versions(self) -> List[str]:
        current_time = time.time()
        if 'node_versions' in self.cache:        
            cache_time = self.cache.get('node_versions_timestamp', 0)
            if current_time - cache_time < self.cache_expiry:
                return self.cache['node_versions']
        try:
            all_versions = []
            page = 1
            max_pages = 50
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                while page <= max_pages:
                    url = f"{self.node_docker_api}?page={page}&page_size=100"
                    async with session.get(url) as response:
                        if response.status != 200:
                            break
                        data = await response.json()
                        tags = data.get("results", [])
                        if not tags:
                            break
                        page_versions = self._extract_valid_node_versions(tags)
                        all_versions.extend(page_versions)
                        if not data.get("next"):
                            break
                        page += 1
                        if len(all_versions) >= 100:
                            break
            all_versions.sort(key=parse_version, reverse=True)
            self.cache['node_versions'] = all_versions
            self.cache['node_versions_timestamp'] = current_time
            return all_versions
        except Exception as e:
            logger.error(f"Error fetching node versions: {e}")
            return self.cache.get('node_versions', [])
    def _extract_valid_node_versions(self, tags: List[Dict]) -> List[str]:
        valid_versions = []
        min_version_parsed = parse_version(self.min_node_version)
        for tag in tags:
            tag_name = tag.get("name", "")
            if any(keyword in tag_name.lower() for keyword in ['nightly', 'dev', 'beta', 'alpha', 'rc', 'latest']):
                continue
            if re.match(r'^\d+\.\d+\.\d+$', tag_name):
                try:
                    tag_version = parse_version(tag_name)
                    if tag_version >= min_version_parsed:
                        valid_versions.append(tag_name)
                except ValueError:
                    continue
        return valid_versions                                   
    async def update_node_version(self, target_version: str) -> Dict[str, Any]:
        result = {
            "success": False,
            "message": "",
            "old_version": None,
            "new_version": target_version,
            "command_output": ""
        }
        try:
            current_version = await self.get_node_current_version()
            result["old_version"] = current_version
            if not re.match(r'^\d+\.\d+\.\d+$', target_version):
                result["message"] = f"❌ Invalid version format: {target_version}\nExpected format: x.y.z (e.g., 0.87.8)"
                return result
            available_versions = await self.fetch_available_versions()
            if target_version not in available_versions:
                result["message"] = f"""❌ Version {target_version} not found
Available versions: {', '.join(available_versions[:10])}{'...' if len(available_versions) > 10 else ''}
Please select a valid version from the list."""
                return result
            if current_version:
                current_parsed = parse_version(current_version)
                target_parsed = parse_version(target_version)
                if target_parsed < current_parsed:
                    logger.warning(f"Downgrading from {current_version} to {target_version}")
                elif target_parsed == current_parsed:
                    result["message"] = f"ℹ️ Already running version {target_version}"
                    result["success"] = True
                    return result
            logger.info(f"Updating node from {current_version} to {target_version}")
            update_command = f"aztec-up -v {target_version}"
            success, output = await self.run_command(update_command)
            result["command_output"] = output
            if success:
                await asyncio.sleep(10)
                new_version = await self.get_node_current_version()
                if new_version == target_version:
                    result["success"] = True
                    result["message"] = f"""✅ Node Update Successful!

📦 Updated: {current_version or 'Unknown'} → {target_version}
🔄 Command: {update_command}
⏰ Time: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

✨ Your Aztec node has been successfully updated to version {target_version}!

🔍 Verify with: aztec -V"""
                else:
                    result["message"] = f"""⚠️ Update Command Completed but Version Mismatch

📦 Expected: {target_version}
📦 Current: {new_version or 'Unknown'}
🔄 Command: {update_command}

The update command ran successfully, but the version check shows a different result.
This might be normal if the node is still starting up.

Wait a few minutes and check again with: aztec -V"""
            else:
                result["message"] = f"""❌ Node Update Failed

🔄 Command: {update_command}
❌ Error Output:
{output[:500]}{'...' if len(output) > 500 else ''}

Common solutions:
• Check if aztec-up command is available
• Ensure sufficient disk space
• Verify network connectivity
• Check if any Aztec processes are running"""
            
            return result
        except Exception as e:
            logger.error(f"Error updating node version: {e}")
            result["message"] = f"❌ Unexpected error during update: {str(e)}"
            return result
    def clear_version_cache(self):
        """Clear version cache để force refresh"""
        self.version_cache.clear()
        logger.info("Version cache cleared")                            
    async def apply_update(self, new_content: str, new_version: str) -> bool:
        """Apply update to bot file only, without restarting external services"""
        backup_path = None
        try:
            backup_path = f"{__file__}.backup.v{self.current_version}.{int(time.time())}"
            shutil.copy2(__file__, backup_path)
            logger.info(f"Created backup: {backup_path}")
            with open(__file__, "w", encoding='utf-8') as f:
                f.write(new_content)
            logger.info(f"Bot file updated from v{self.current_version} to v{new_version}")
            return True
        except Exception as e:
            logger.error(f"Bot update failed: {e}")
            try:
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, __file__)
                    logger.info("Restored from backup after failed update")
            except Exception as restore_error:
                logger.error(f"Failed to restore backup: {restore_error}")
            return False                
    async def check_rpc_health(self, exec_rpc: str, beacon_rpc: str = None) -> Dict[str, Any]:
        """Check RPC and Beacon health"""
        result = {
            "success": False,
            "exec_rpc": exec_rpc,
            "beacon_rpc": beacon_rpc,
            "exec_status": {"healthy": False, "block_number": None, "http_code": None},
            "beacon_status": {"healthy": False, "version": None, "http_code": None, "head_slot": None},
            "blob_status": {"success_rate": 0, "total_blobs": 0, "errors": 0},
            "message": ""
        }
    
        try:
            exec_payload = {
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }
        
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                try:
                    async with session.post(exec_rpc, json=exec_payload) as response:
                        result["exec_status"]["http_code"] = response.status
                        if response.status == 200:
                            data = await response.json()
                            block_hex = data.get("result")
                            if block_hex:
                                block_number = int(block_hex, 16)
                                result["exec_status"]["healthy"] = True
                                result["exec_status"]["block_number"] = block_number
                            else:
                                result["exec_status"]["healthy"] = False
                        else:
                            result["exec_status"]["healthy"] = False
                except Exception as e:
                    logger.error(f"Error checking Exec RPC: {e}")
                    result["exec_status"]["healthy"] = False
                    result["exec_status"]["http_code"] = "unreachable"
            
                if beacon_rpc:
                    try:
                        version_url = f"{beacon_rpc}/eth/v1/node/version"
                        async with session.get(version_url) as response:
                            result["beacon_status"]["http_code"] = response.status
                            if response.status == 200:
                                data = await response.json()
                                version = data.get("data", {}).get("version")
                                if version:
                                    result["beacon_status"]["healthy"] = True
                                    result["beacon_status"]["version"] = version
                                
                                    head_url = f"{beacon_rpc}/eth/v1/beacon/headers/head"
                                    async with session.get(head_url) as head_response:
                                        if head_response.status == 200:
                                            head_data = await head_response.json()
                                            head_slot = head_data.get("data", {}).get("header", {}).get("message", {}).get("slot")
                                            if head_slot:
                                                result["beacon_status"]["head_slot"] = int(head_slot)
                                                await self._check_blob_sidecars(session, beacon_rpc, int(head_slot), result)
                                            else:
                                                result["beacon_status"]["healthy"] = False
                                        else:
                                            result["beacon_status"]["healthy"] = False
                    except Exception as e:
                        logger.error(f"Beacon RPC error: {e}")
                        result["beacon_status"]["healthy"] = False
                        result["beacon_status"]["http_code"] = "unreachable"
        
            result["message"] = self._format_rpc_health_message(result)
            result["success"] = True
        
        except Exception as e:
            logger.error(f"RPC health check error: {e}")
            result["message"] = f"❌ Error checking RPC health: {str(e)}"
        return result                                                 

    async def _check_blob_sidecars(self, session, beacon_rpc: str, head_slot: int, result: Dict):
        """Check blob sidecars"""
        total_slots = 10
        slots_with_blobs = 0
        total_blobs = 0
        errors = 0
        for i in range(total_slots):
            slot = head_slot - i
            try:
                blob_url = f"{beacon_rpc}/eth/v1/beacon/blob_sidecars/{slot}"
                async with session.get(blob_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        data = await response.json()
                        blob_count = len(data.get("data", []))
                        if blob_count > 0:
                            slots_with_blobs += 1
                            total_blobs += blob_count
                    elif response.status == 404:
                        pass
                    else:
                        errors += 1
            except Exception:
                errors += 1
        success_rate = (slots_with_blobs / total_slots) * 100 if total_slots > 0 else 0
        result["blob_status"] = {
        "success_rate": success_rate,
        "total_blobs": total_blobs,
        "errors": errors,
        "slots_checked": total_slots,
        "slots_with_blobs": slots_with_blobs
    }

    def _format_rpc_health_message(self, result: Dict) -> str:
        """Format RPC health message"""
        exec_status = result["exec_status"]
        beacon_status = result["beacon_status"]
        blob_status = result["blob_status"]
    
        if exec_status["healthy"]:
            exec_line = f"✅ Execution RPC: Healthy (Block: {exec_status['block_number']})"
        else:
            http_code = exec_status.get("http_code", "unknown")
            exec_line = f"❌ Execution RPC: Unhealthy (HTTP: {http_code})"
    
        beacon_line = "ℹ️ Beacon RPC: Not provided"
        blob_line = ""
        blob_details = ""
    
        if result["beacon_rpc"]:
            if beacon_status["healthy"]:
                version = beacon_status.get("version", "unknown")
                beacon_line = f"✅ Beacon RPC: Healthy (Version: {version})"
                if beacon_status.get("head_slot"):
                    success_rate = blob_status["success_rate"]
                    if success_rate >= 75:
                        blob_icon = "🟢"
                        blob_status_text = "HEALTHY"
                    elif success_rate >= 25:
                        blob_icon = "🟡"
                        blob_status_text = "WARNING"
                    else:
                        blob_icon = "🔴"
                        blob_status_text = "CRITICAL"
                    blob_line = f"{blob_icon} Blob Success: {blob_status['slots_with_blobs']}/{blob_status['slots_checked']} slots ({success_rate:.1f}%) - {blob_status_text}"
                    blob_details = f"📊 Total Blobs: {blob_status['total_blobs']} | Errors: {blob_status['errors']}"
                else:
                    blob_line = "⚠️ Blob Check: Could not get head slot"
            else:
                http_code = beacon_status.get("http_code", "unknown")
                beacon_line = f"❌ Beacon RPC: Unhealthy (HTTP: {http_code})"
    
        message_parts = [
            "🔍 RPC Health Check Results",
            "",
            exec_line,
            beacon_line
        ]
    
        if blob_line:
            message_parts.extend(["", blob_line])
        if blob_details:
            message_parts.append(blob_details)
    
        message_parts.extend([
            "",
            "📋 Status Guide:",
            "• 🟢 HEALTHY: ≥75% blob success",
            "• 🟡 WARNING: 25%-75% blob success", 
            "• 🔴 CRITICAL: <25% blob success"
        ])
    
        return "\n".join(message_parts)
                                            

    async def check_miss_rate_alert(self) -> Optional[Dict[str, Any]]:
        """Kiểm tra miss rate và gửi cảnh báo nếu cần"""
        try:
            # Lấy validator status
            validator_status = await self.fetch_validator_data()
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
            
            alert_message = f"""🚨 VALIDATOR ALERT 🚨

❌ High Miss Rate Detected!

📊 Miss Rate: {miss_rate:.1f}% (> 30%)
🎯 Validator Index: {validator_index}
🔗 Address: {validator_address[:10]}...{validator_address[-8:]}

📈 Attestation Stats:
• Total: {total_attestations}
• Missed: {missed_attestations}
• Success: {total_attestations - missed_attestations}

⚠️ Action Required:
• Check node connectivity
• Verify synchronization status
• Review system resources
• Check network latency

⏰ Time: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"""

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
        """Get remote version with proper parsing"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.remote_version_url) as response:
                    if response.status == 200:
                        content = await response.text()
                    
                    # Try JSON format first
                        try:
                            data = json.loads(content)
                            if 'version' in data:
                                return data['version']
                        except json.JSONDecodeError:
                            pass
                    
                    # Try version pattern matching
                        patterns = [
                            r'"?version"?\s*:\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?',
                            r'([0-9]+\.[0-9]+\.[0-9]+)',
                            r'v([0-9]+\.[0-9]+\.[0-9]+)'
                        ]
                    
                        for pattern in patterns:
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                return match.group(1)
                    
                        logger.warning(f"Could not parse version from: {content[:100]}")
                        return None
                    return None
        except Exception as e:
            logger.error(f"Error getting remote version: {e}")
            return None
    async def get_bot_remote_version(self) -> Optional[str]:
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

    async def check_bot_update(self) -> bool:
        """Check for auto-update"""
        result = {
            "success": False,
            "current_version": self.bot_version,
            "remote_version": None,
            "update_available": False,
            "message": ""
        }
        try:
            remote_version = await self.get_bot_remote_version()
            if not remote_version:
                result["message"] = "❌ Cannot fetch remote bot version"
                return result
            result["remote_version"] = remote_version
            result["success"] = True
            current_parsed = parse_version(self.bot_version)
            remote_parsed = parse_version(remote_version)                                 
            if remote_parsed > current_parsed:
                result["update_available"] = True
                result["message"] = f"""🔄 Bot Update Available!

📦 Current Version: {self.bot_version}
🆕 Latest Version: {remote_version}
📊 Status: Update available

Ready to update your monitoring bot."""
            else:
                result["message"] = f"""✅ Bot Up to Date

📦 Current Version: {self.bot_version}
🌐 Latest Version: {remote_version}
📊 Status: No update needed"""
            
            return result
        except Exception as e:
            logger.error(f"Error checking bot update: {e}")
            result["message"] = f"❌ Error checking bot update: {str(e)}"
            return result    
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
                    message = groups[1].strip() if len(groups) > 1 and groups[1] else ""

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
            total_blockmissed = validator_data.get("totalBlocksMissed", 0)
            total_epochs = validator_data.get("totalParticipatingEpochs", 0)
        
            status_icon = "🟢" if status == "Active" else "🔴" if status == "Inactive" else "🟡"
            slashed_icon = "⚠️" if slashed else "✅"    
        
            recent_epoch_stats = validator_data.get("recentEpochStats", [])
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
        
            validator_info = f"""🎯 Validator Status: {status} {status_icon}
🏷️ Index: {index}
💰 Balance: {balance}
{slashed_icon} Slashed: {'Yes' if slashed else 'No'}

📊 Attestations Performance:
• Total Attestations: {success_total}
• Successful: {total_success}
• Missed: {total_missed}
• Success Rate: {success_rate:.1f}%
• Miss Rate: {miss_rate:.1f}%

📈 Epoch and Proposal Participation:
• Total Epochs: {total_epochs}
• Blocks Proposed: {total_proposed}
• Blocks Mined: {total_blockmined}
• Blocks Missed: {total_blockmissed}
• Proposal Miss Rate: {proposal_missrate:.1f}%

🔗 Address: {address[:10]}...{address[-8:]}"""
        
            return validator_info
        except Exception as e:
            logger.error(f"Error formatting validator info: {e}")
            return f"❌ Error formatting validator data: {str(e)}"
    
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
            rf'<img src="/img/flag_greengif".*?>.*?Port.*?{port}.*?is open',
            rf'Port.*?{port}.*?is open',
            r'<img src="/img/flag_greengif"',
            r'flag_greengif'
        ]
            closed_patterns = [
            rf'<img src="/img/flag_redgif".*?>.*?Port.*?{port}.*?is closed',
            rf'Port.*?{port}.*?is closed',
            r'<img src="/img/flag_redgif"',
            r'flag_redgif'
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
start_time = time.time()
async def handle_port_check_menu(query, context=None) -> None:
    """Handle port check menu"""
    text = """🔍 Port Check Tool

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
    
    # Sửa lỗi: Set đúng state cho port check
    if context:
        context.user_data["awaiting_port_check"] = True  # Thay đổi này
        context.user_data.pop("port_check_state", None)  # Xóa state cũ


async def handle_rpc_check_custom(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    user_id = query.from_user.id
    if not monitor.check_authorization(user_id):
        await query.answer("❌ Unauthorized access!")
        return
    text = """🔍 RPC Health Check

Enter RPC details in one of these formats:

Single RPC:
`http://127.0.0.1:8545`
`http://your-ip:8545`

RPC + Beacon:
`http://127.0.0.1:8545,http://127.0.0.1:3500`
`http://your-ip:8545,http://your-ip:3500`

Examples:
• `http://127.0.0.1:8545` - Local execution only
• `http://192.168.1.100:8545,http://192.168.1.100:3500` - Both RPC & Beacon
• `https://eth-sepolia.g.alchemy.com/v2/your-key` - Remote RPC

Please enter your RPC URL(s):"""
    escaped_text = escape_markdown_v2(text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
        ]),
        parse_mode="MarkdownV2"
    )
    context.user_data["awaiting_rpc_check"] = True    

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

        await update.message.reply_text(escape_markdown_v2(text), parse_mode="MarkdownV2")
        
    elif context.user_data.get("awaiting_monitor_interval"):
        interval_text = update.message.text.strip()
        context.user_data["awaiting_monitor_interval"] = False
        try:
            interval = int(interval_text)
            if interval < 60:
                await update.message.reply_text("❌ Minimum interval is 60 seconds!")
                return
            if monitor.monitoring_active:
                monitor.stop_monitoring()
            monitor.start_monitoring(interval)
            success_text = f"""✅ Custom Monitoring Started!

⏱️ Check Interval: {interval} seconds ({interval//60} minutes)
🔍 Miss Rate Alert: > 30%
🔕 Alert Cooldown: 30 minutes

Your custom monitoring interval has been applied."""
            escaped_text = escape_markdown_v2(success_text)
            await update.message.reply_text(escaped_text, parse_mode="MarkdownV2")
        except ValueError:
            await update.message.reply_text("❌ Invalid interval! Please enter a valid number in seconds.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error setting interval: {str(e)}")
            
    elif context.user_data.get("awaiting_rpc_check"):
        input_text = update.message.text.strip()
        context.user_data["awaiting_rpc_check"] = False
        try:
            if "," in input_text:
                parts = input_text.split(",", 1)
                exec_rpc = parts[0].strip()
                beacon_rpc = parts[1].strip()
            else:
                exec_rpc = input_text.strip()
                beacon_rpc = None
            
            if not (exec_rpc.startswith("http://") or exec_rpc.startswith("https://")):
                await update.message.reply_text("❌ Execution RPC must start with http:// or https://")
                return
            
            if beacon_rpc and not (beacon_rpc.startswith("http://") or beacon_rpc.startswith("https://")):
                await update.message.reply_text("❌ Beacon RPC must start with http:// or https://")
                return
            
            checking_msg = f"🔍 Checking RPC health...\n\n⏳ Testing execution RPC: {exec_rpc}"
            if beacon_rpc:
                checking_msg += f"\n⏳ Testing beacon RPC: {beacon_rpc}"
            checking_msg += "\n\nPlease wait..."
            await update.message.reply_text(checking_msg)
            
            result = await monitor.check_rpc_health(exec_rpc, beacon_rpc)
            if result["success"]:
                text = result["message"]
            else:
                text = f"❌ RPC Health Check Failed\n\n{result['message']}"
            
            escaped_text = escape_markdown_v2(text)
            await update.message.reply_text(
                escaped_text,
                parse_mode="MarkdownV2"
            )
        except Exception as e:
            await update.message.reply_text(f"❌ Error processing RPC check: {str(e)}")
    
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
                text = f"""🔍 Port Check Result

{status_icon} Status: {status_text}
🌐 IP Address: {result['ip_address']}
🔌 Port: {result['port']}

{result['message']}"""
                if result["is_open"]:
                    text += f"""

✅ Port {port} is accessible from the internet
• Services can accept incoming connections
• Port forwarding is working correctly
• No firewall blocking this port"""
                else:
                    text += f"""

❌ Port {port} is not accessible from the internet

Possible causes:
• Port is not open/listening
• Firewall blocking the port
• Router not forwarding the port
• Service not running on this port

To fix:
• Check if service is running
• Configure port forwarding on router
• Allow port through firewall"""

            else:
                text = f"""🔍 Port Check Result

❌ Error checking port {port}

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
    text = "📥 Please enter the port number your Aztec RPC is running on (e.g. 8080, 9000):"
    escaped_text = escape_markdown_v2(text)    
    await query.edit_message_text(escaped_text, parse_mode="MarkdownV2")
    context.user_data["awaiting_port"] = True        
async def handle_validator_status(query) -> None:
    """Handle validator status check"""
    loading_msg = """🔍 Checking validator status...
⏳ Getting validator owner address...
⏳ Fetching validator data...
Please wait..."""
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        # Lấy validator address trước
        validator_address = await monitor.get_validator_owner_address()
        if not validator_address:
            text = """❌ Validator Address Not Found
            
Could not retrieve validator owner address from container logs.

Possible causes:
• Container not running
• No validator address in logs yet
• Container logs not accessible

Try restarting the service or check container status."""
            
            await query.edit_message_text(
                escape_markdown_v2(text),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
                    [InlineKeyboardButton("🔄 Retry", callback_data="validator_status")],
                ]),
                parse_mode="MarkdownV2"
            )
            return
        
        # Fetch validator data với address
        validator_data = await monitor.fetch_validator_data(validator_address)
        
        if validator_data:
            status = {
                "success": True,
                "validator_found": True,
                "validator_data": validator_data,
                "message": monitor.format_validator_info(validator_data)
            }
        else:
            status = {
                "success": False,
                "validator_found": False,
                "message": f"❌ Validator not found in network for address: {validator_address}"
            }
        
        # Format message
        if status["success"]:
            text = f"🎯 Validator Status\n\n{status['message']}"
        else:
            text = f"🎯 Validator Status\n\n{status['message']}"
        
        back_button = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
            [InlineKeyboardButton("🔄 Retry", callback_data="validator_status")],
        ])
        
        try:
            escaped_text = escape_markdown_v2(text)
            await query.edit_message_text(
                escaped_text, reply_markup=back_button, parse_mode="MarkdownV2"
            )
        except Exception as e:
            logger.warning(f"Markdown parsing failed, using plain text: {e}")
            plain_text = text.replace("*", "").replace("`", "").replace("\\", "")
            await query.edit_message_text(plain_text, reply_markup=back_button)
            
    except Exception as e:
        logger.error(f"Error in validator status: {e}")
        error_text = f"❌ Error checking validator status: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )

async def handle_peer_status(query) -> None:
    """Handle peer status check"""
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
            text = f"🌐 Aztec Peer Status\n\n{status['message']}"
        else:
            text = f"🌐 Aztec Peer Status\n\n{status['message']}"
    else:
        text = f"🌐 Aztec Peer Status\n\n{status['message']}"

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


async def handle_node_management_menu(query) -> None:
    text = """🏗️ Node Management

Manage your Aztec node version and updates efficiently

Features:
• Check current node version
• Browse available versions
• Quick update to latest
• Smart caching system
• Detailed update progress

Select an option:"""
    
    await query.edit_message_text(
        text,
        reply_markup=create_node_management_menu(),
        parse_mode="MarkdownV2",
    )
async def handle_node_current_version(query) -> None:
    """Handle current node version display"""
    loading_msg = "🔍 Checking current node version...\n⏳ Please wait..."
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        current_version = await monitor.get_node_current_version()
        if current_version:
            text = f"""📦 Current Node Version

🏷️ Version: {current_version}
🐳 Source: Aztec Docker Container
⏰ Checked: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

✅ Node version detected successfully"""
        else:
            text = """❌ Version Detection Failed

Could not determine current node version.

Possible causes:
• Node not running
• aztec command not available
• Container not accessible

Try restarting the service or check container status."""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error checking current version: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )
async def handle_node_check_update(query) -> None:
    """Handle node update check"""
    loading_msg = """🔍 Checking for node updates...

⏳ Getting current version...
⏳ Fetching available versions...
⏳ Comparing versions...

Please wait..."""
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        result = await monitor.check_node_update()
        
        if result["success"]:
            text = result["message"]
            
            # Add action buttons based on update availability
            if result["update_available"]:
                buttons = [
                    [
                        InlineKeyboardButton("🚀 Quick Update", callback_data=f"node_update_{result['latest_version']}"),
                        InlineKeyboardButton("📋 All Versions", callback_data="node_version_list")
                    ],
                    [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
                ]
            else:
                buttons = [
                    [
                        InlineKeyboardButton("🔍 Check Again", callback_data="node_check_update"),
                        InlineKeyboardButton("📋 All Versions", callback_data="node_version_list")
                    ],
                    [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
                ]
        else:
            text = result["message"]
            buttons = [
                [
                    InlineKeyboardButton("🔄 Retry", callback_data="node_check_update"),
                    InlineKeyboardButton("🔙 Back", callback_data="node_management")
                ]
            ]
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error checking node updates: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )

async def handle_node_update_execute(query, target_version: str) -> None:
    """Handle node version update execution"""
    loading_msg = f"""🔄 Updating Node to v{target_version}

⏳ Validating version...
⏳ Stopping current node...
⏳ Downloading new version...
⏳ Starting updated node...

This may take several minutes. Please wait..."""
    
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        result = await monitor.update_node_version(target_version)
        
        if result["success"]:
            text = result["message"]
            buttons = [
                [
                    InlineKeyboardButton("✅ Check Version", callback_data="node_current_version"),
                    InlineKeyboardButton("🔍 Check Updates", callback_data="node_check_update")
                ],
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]
        else:
            text = result["message"]
            buttons = [
                [
                    InlineKeyboardButton("🔄 Retry", callback_data=f"node_update_{target_version}"),
                    InlineKeyboardButton("🔙 Back", callback_data="node_management")
                ]
            ]
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error updating node: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )

async def handle_bot_check_update(query) -> None:
    """Handle bot update check"""
    loading_msg = """🔍 Checking for bot updates...

⏳ Fetching remote version...
⏳ Comparing versions...
⏳ Preparing update info...

Please wait..."""
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        result = await monitor.check_bot_update()
        
        if result["success"]:
            text = result["message"]
            
            if result["update_available"]:
                buttons = [
                    [
                        InlineKeyboardButton("✅ Update Now", callback_data="bot_apply_update"),
                        InlineKeyboardButton("❌ Cancel", callback_data="settings_menu")
                    ]
                ]
            else:
                buttons = [
                    [
                        InlineKeyboardButton("🔍 Check Again", callback_data="bot_check_update"),
                        InlineKeyboardButton("🔙 Back", callback_data="settings_menu")
                    ]
                ]
        else:
            text = result["message"]
            buttons = [
                [
                    InlineKeyboardButton("🔄 Retry", callback_data="bot_check_update"),
                    InlineKeyboardButton("🔙 Back", callback_data="settings_menu")
                ]
            ]
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error checking bot updates: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
            ]),
            parse_mode="MarkdownV2"
        )
          
async def handle_apply_update(query, context) -> None:
    """Handle bot update application"""
    loading_msg = """🔄 Applying Bot Update

⏳ Downloading latest version...
⏳ Creating backup...
⏳ Applying update...

Please wait..."""
    
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        # Get remote version and content
        remote_version = await monitor.get_bot_remote_version()
        if not remote_version:
            await query.edit_message_text(
                "❌ Cannot fetch remote version",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
                ])
            )
            return
        
        # Download remote content
        async with aiohttp.ClientSession() as session:
            async with session.get(monitor.remote_file_url) as response:
                if response.status == 200:
                    new_content = await response.text()
                else:
                    await query.edit_message_text(
                        f"❌ Failed to download update (HTTP {response.status})",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
                        ])
                    )
                    return
        
        # Apply update
        success = await monitor.apply_update(new_content, remote_version)
        
        if success:
            text = f"""✅ Bot Update Successful!

📦 Updated: {monitor.bot_version} → {remote_version}
⏰ Time: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

🔄 Bot will restart automatically to apply changes."""
        else:
            text = """❌ Bot Update Failed

The update could not be applied. Please check logs for details."""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
            ]),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error applying update: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
            ]),
            parse_mode="MarkdownV2"
        )


async def handle_node_version_list(query) -> None:
    """Handle comprehensive version list với pagination"""
    loading_msg = "📋 Loading comprehensive version list...\n⏳ Please wait..."
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        available_versions = await monitor.fetch_available_versions(use_cache=False)
        current_version = await monitor.get_node_current_version()
        
        if not available_versions:
            text = "❌ Cannot load version list from Docker Hub"
            await query.edit_message_text(
                escape_markdown_v2(text),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
                ]),
                parse_mode="MarkdownV2"
            )
            return
        
        # Tạo danh sách versions với status
        version_lines = []
        for i, version in enumerate(available_versions[:30]):  # Top 30
            if version == current_version:
                status = " (current)"
                icon = "📍"
            elif current_version and parse_version(version) > parse_version(current_version):
                status = " (newer)"
                icon = "🆕"
            elif current_version and parse_version(version) < parse_version(current_version):
                status = " (older)"
                icon = "📦"
            else:
                status = ""
                icon = "📦"
            
            version_lines.append(f"{icon} {version}{status}")
        
        text = f"""📋 Available Versions

🏷️ Current: {current_version or 'Unknown'}
📊 Total Available: {len(available_versions)}
🔝 Showing top 30 versions:

{chr(10).join(version_lines)}

{'...' if len(available_versions) > 30 else ''}

Select an action:"""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔄 Update Menu", callback_data="node_update_menu"),
                    InlineKeyboardButton("🔍 Check Updates", callback_data="node_check_update")
                ],
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error loading version list: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )

async def handle_node_clear_cache(query) -> None:
    """Handle clearing version cache"""
    monitor.clear_version_cache()
    
    text = """🗑️ Cache Cleared

Version cache has been cleared successfully.
Next version check will fetch fresh data from Docker Hub.

This is useful if you suspect the version list is outdated."""
    
    await query.edit_message_text(
        escape_markdown_v2(text),
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔍 Check Updates", callback_data="node_check_update")],
            [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
        ]),
        parse_mode="MarkdownV2"
    )


def create_monitor_menu() -> InlineKeyboardMarkup:
    """Create monitoring control menu"""
    status_text = "🟢 Stop Monitor" if monitor.monitoring_active else "🔴 Start Monitor"
    status_callback = "stop_monitor" if monitor.monitoring_active else "start_monitor"
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📊 Monitor Status", callback_data="monitor_status"),
                InlineKeyboardButton(status_text, callback_data=status_callback),
            ],
            [
                InlineKeyboardButton("⚙️ Custom Interval", callback_data="monitor_custom"),
                InlineKeyboardButton("🔔 Test Alert", callback_data="test_alert"),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]    
        ]
    )    

def create_main_menu() -> InlineKeyboardMarkup:
    """Create optimized main menu with clear categorization"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🎯 Validator", callback_data="validator_status"),
            InlineKeyboardButton("📊 System", callback_data="system_menu"),
        ],
        [
            InlineKeyboardButton("🏗️ Node", callback_data="node_management"),
            InlineKeyboardButton("📝 Logs", callback_data="logs_menu"),
        ],
        [
            InlineKeyboardButton("🔧 Tools", callback_data="tools_menu"),
            InlineKeyboardButton("⚙️ Settings", callback_data="settings_menu"),
        ]
    ])
def create_system_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📊 Service Status", callback_data="status"),
            InlineKeyboardButton("💻 Resources", callback_data="resources"),
        ],
        [
            InlineKeyboardButton("🔄 Sync Status", callback_data="sync_custom"),
            InlineKeyboardButton("🌐 Peer Status", callback_data="peer_status"),
        ],
        [
            InlineKeyboardButton("⚡ Quick Actions", callback_data="quick_actions"),
            InlineKeyboardButton("🔙 Back", callback_data="main_menu"),
        ]
    ])

def create_node_management_menu() -> InlineKeyboardMarkup:
    """Create streamlined node management menu"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📦 Current version", callback_data="node_current_version"),
        ],
        [
            InlineKeyboardButton("🔍 Check Updates", callback_data="node_check_update"),
            InlineKeyboardButton("🚀 Quick Update", callback_data="node_quick_update"),
        ],
        [
            InlineKeyboardButton("📋 Browse Versions", callback_data="node_version_list"),
            InlineKeyboardButton("🗑️ Clear Cache", callback_data="node_clear_cache"),
        ],
        [
            InlineKeyboardButton("🔙 Back", callback_data="main_menu")
        ]
    ])
def create_smart_logs_menu() -> InlineKeyboardMarkup:
    """Create intelligent logs menu"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔥 Recent (5m)", callback_data="logs_recent"),
            InlineKeyboardButton("❌ Errors Only", callback_data="logs_error"),
        ],
        [
            InlineKeyboardButton("🎯 Validator Logs", callback_data="comp_validator"),
            InlineKeyboardButton("🌐 P2P Logs", callback_data="comp_p2p-client"),
        ],
        [
            InlineKeyboardButton("📊 All Levels", callback_data="logs_all"),
            InlineKeyboardButton("🎨 Clean View", callback_data="logs_clean"),
        ],
        [
            InlineKeyboardButton("🔧 More Filters", callback_data="logs_advanced"),
            InlineKeyboardButton("🔙 Back", callback_data="main_menu"),
        ]
    ])
async def update_message_with_breadcrumb(query, text: str, current_menu: str, reply_markup):
    """Add breadcrumb navigation to messages"""
    breadcrumbs = {
        "main_menu": "🏠 Home",
        "system_menu": "🏠 Home > 📊 System",
        "node_management": "🏠 Home > 🏗️ Node",
        "logs_menu": "🏠 Home > 📝 Logs",
        "tools_menu": "🏠 Home > 🔧 Tools",
        "settings_menu": "🏠 Home > ⚙️ Settings"
    }
    
    breadcrumb = breadcrumbs.get(current_menu, "🏠 Home")
    full_text = f"{breadcrumb}\n\n{text}"
    
    await query.edit_message_text(
        escape_markdown_v2(full_text),
        reply_markup=reply_markup,
        parse_mode="MarkdownV2"
    )
async def show_loading_with_steps(query, steps: list, current_step: int = 0):
    """Show loading with step progress"""
    progress_text = "🔄 Processing...\n\n"
    
    for i, step in enumerate(steps):
        if i < current_step:
            progress_text += f"✅ {step}\n"
        elif i == current_step:
            progress_text += f"⏳ {step}...\n"
        else:
            progress_text += f"⏸️ {step}\n"
    
    progress_text += f"\n📊 Progress: {current_step}/{len(steps)}"
    
    await query.edit_message_text(progress_text, reply_markup=None)
async def handle_error_with_retry(query, error_msg: str, retry_callback: str, back_callback: str = "main_menu"):
    """Handle errors with user-friendly retry options"""
    error_text = f"""❌ Operation Failed

{error_msg}

What would you like to do?"""
    
    retry_menu = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔄 Try Again", callback_data=retry_callback),
            InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"),
        ],
        [
            InlineKeyboardButton("🔙 Go Back", callback_data=back_callback),
            InlineKeyboardButton("📞 Get Help", callback_data="help_menu"),
        ]
    ])
    
    await query.edit_message_text(
        escape_markdown_v2(error_text),
        reply_markup=retry_menu,
        parse_mode="MarkdownV2"
    )
def get_contextual_shortcuts(current_menu: str) -> list:
    """Get relevant shortcuts based on current context"""
    shortcuts = {
        "validator_status": [
            ("🔄 Refresh", "validator_status"),
            ("📝 Validator Logs", "comp_validator")
        ],
        "node_management": [
            ("🚀 Quick Update", "node_quick_update"),
            ("📊 System Status", "status")
        ],
        "logs_menu": [
            ("❌ Show Errors", "logs_error"),
            ("🎯 Validator", "comp_validator")
        ]
    }
    return shortcuts.get(current_menu, [])

def create_tools_menu() -> InlineKeyboardMarkup:
    """Create tools and diagnostics submenu"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔗 RPC Health", callback_data="rpc_check"),
            InlineKeyboardButton("🔍 Port Check", callback_data="port_check"),
        ],
        [
            InlineKeyboardButton("🏗️ Node Management", callback_data="node_management"),
            InlineKeyboardButton("📊 Monitor Control", callback_data="monitor_menu"),
        ],
        [
            InlineKeyboardButton("📋 System Info", callback_data="system_menu"),
            InlineKeyboardButton("🔙 Back", callback_data="main_menu")
        ]
    ])
def create_settings_menu() -> InlineKeyboardMarkup:
    """Create settings menu với bot update options"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📦 Bot Version", callback_data="bot_current_version"),
            InlineKeyboardButton("🔄 Check Bot Update", callback_data="bot_check_update"),
        ],
        [
            InlineKeyboardButton("⚙️ Bot Settings", callback_data="bot_settings"),
            InlineKeyboardButton("📊 Statistics", callback_data="bot_stats"),
        ],
        [
            InlineKeyboardButton("🔙 Back", callback_data="main_menu")
        ]
    ])

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
    """Enhanced start command with quick overview"""
    user_id = update.effective_user.id
    if not monitor.check_authorization(user_id):
        await update.message.reply_text("❌ Unauthorized access!")
        return

    # Get quick status for welcome
    try:
        service_status = await monitor.get_service_status()
        current_version = await monitor.get_node_current_version()
        
        status_icon = "🟢" if service_status["active"] else "🔴"
        version_text = f"v{current_version}" if current_version else "Unknown"
        
        welcome_text = f"""🚀 Aztec Node Monitor

{status_icon} Service: {'Running' if service_status['active'] else 'Stopped'}
📦 Version: {version_text}
⏰ {datetime.now().strftime('%H:%M %d/%m/%Y')}

Choose an option to get started:"""
        
    except:
        welcome_text = """🚀 Aztec Node Monitor

Welcome to your node monitoring dashboard!

Choose an option to get started:"""

    # Add quick actions to main menu
    enhanced_menu = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🎯 Validator", callback_data="validator_status"),
            InlineKeyboardButton("📊 System", callback_data="system_menu"),
        ],
        [
            InlineKeyboardButton("🏗️ Node", callback_data="node_management"),
            InlineKeyboardButton("📝 Logs", callback_data="logs_menu"),
        ],
        [
            InlineKeyboardButton("🔧 Tools", callback_data="tools_menu"),
            InlineKeyboardButton("⚙️ Settings", callback_data="settings_menu"),
        ]
    ])

    await update.message.reply_text(
        escape_markdown_v2(welcome_text),
        reply_markup=enhanced_menu,
        parse_mode="MarkdownV2",
    )



async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Enhanced button handler for simplified menu"""
    query = update.callback_query
    user_id = query.from_user.id

    if not monitor.check_authorization(user_id):
        await query.answer("❌ Unauthorized access!", show_alert=True)
        return

    await query.answer()
    if query.data == "node_management":
        await handle_node_management_menu(query)
    elif query.data == "node_current_version":
        await handle_node_current_version(query)
    elif query.data == "node_check_update":
        await handle_node_check_update(query)
    elif query.data == "node_quick_update":
        await handle_node_quick_update(query)
    elif query.data == "node_version_list":
        await handle_node_version_list(query)
    elif query.data == "node_clear_cache":
        await handle_node_clear_cache(query)
    elif query.data.startswith("node_update_"):
        version = query.data.replace("node_update_", "")
        await handle_node_update_execute(query, version)
    elif query.data == "bot_current_version":
        await handle_bot_current_version(query)
    elif query.data == "bot_check_update":
        await handle_bot_check_update(query)
    elif query.data == "bot_apply_update":
        await handle_apply_update(query, context)    

    # Main navigation
    elif query.data == "main_menu":
        await query.edit_message_text(
            "🏠 *Main Menu*\n\nSelect a category:",
            reply_markup=create_main_menu(),
            parse_mode="MarkdownV2",
        )
    
    # Submenu navigation
    elif query.data == "system_menu":
        text = """📊 *System Monitoring*

Monitor your Aztec node's core components and performance metrics

Select an option:"""
        await query.edit_message_text(
            text,
            reply_markup=create_system_menu(),
            parse_mode="MarkdownV2",
        )
    
    elif query.data == "tools_menu":
        text = """🔧 *Tools & Diagnostics*

Access logging, network diagnostics, and monitoring tools

Select an option:"""
        await query.edit_message_text(
            text,
            reply_markup=create_tools_menu(),
            parse_mode="MarkdownV2",
        )
    elif query.data == "node_management":
        text = """🏗️ *Node Management*

Manage your Aztec node version and updates efficiently

Features:
• Quick update to latest version
• Browse all available versions  
• Smart caching for faster responses
• Detailed update progress tracking

Select an option:"""
        await query.edit_message_text(
            text,
            reply_markup=create_node_management_menu(),
            parse_mode="MarkdownV2",
        )    
    elif query.data == "node_quick_update":
        await handle_node_quick_update(query)
    elif query.data == "node_version_list":
        await handle_node_version_list(query)
    elif query.data == "node_clear_cache":
        await handle_node_clear_cache(query)
    elif query.data == "settings_menu":
        await handle_settings_menu(query)
    # System Status handlers
    elif query.data == "status":
        await handle_status(query)
    elif query.data == "resources":
        await handle_resources(query)
    elif query.data == "sync_custom":
        await handle_sync_status_custom(update, context)
    elif query.data == "peer_status":
        await handle_peer_status(query)
    elif query.data == "refresh_system":
        await handle_refresh_system(query)
    
    # Validator handler
    elif query.data == "validator_status":
        await handle_validator_status(query)
    
    # Tools & Logs handlers
    elif query.data == "logs_menu":
        await handle_logs_menu(query)
    elif query.data == "port_check":
        await handle_port_check_menu(query, context)
    elif query.data == "rpc_check":
        await handle_rpc_check_custom(update, context)
    elif query.data == "monitor_menu":
        await handle_monitor_menu(query)
    
    # Settings handlers
    elif query.data == "version_info":
        await handle_version_info(query)
    elif query.data == "apply_update":
        await handle_apply_update(query, context)
    elif query.data == "bot_settings":
        await handle_bot_settings(query)
    elif query.data == "bot_stats":
        await handle_bot_stats(query)
    
    # Bot Settings sub-handlers
    elif query.data == "toggle_monitor":
        await handle_toggle_monitor(query)
    elif query.data == "monitor_intervals":
        await handle_monitor_intervals(query)
    elif query.data == "notification_settings":
        await handle_notification_settings(query)
    elif query.data == "log_settings":
        await handle_log_settings(query)
    elif query.data.startswith("interval_"):
        interval = int(query.data.replace("interval_", ""))
        await handle_set_interval(query, interval)
    
    # Legacy handlers (keep for backward compatibility)
    elif query.data == "monitor_status":
        await handle_monitor_status(query)
    elif query.data == "start_monitor":
        await handle_start_monitor(query, context)
    elif query.data == "stop_monitor":
        await handle_stop_monitor(query)
    elif query.data == "monitor_custom":
        await handle_monitor_custom(query, context)
    elif query.data == "test_alert":
        await handle_test_alert(query)
    elif query.data == "logs_clean":
        await handle_logs_enhanced(query, clean_view=True)
    elif query.data.startswith("logs_"):
        log_level = query.data.replace("logs_", "")
        await handle_logs_enhanced(query, log_level=log_level)
    elif query.data.startswith("comp_"):
        component = query.data.replace("comp_", "")
        await handle_logs_enhanced(query, component=component)

async def handle_settings_menu(query) -> None:
    """Handle settings menu display"""
    text = """⚙️ *Settings & Maintenance*

Configure bot settings, check for updates, and view system information

Select an option:"""
    
    await query.edit_message_text(
        text,
        reply_markup=create_settings_menu(),
        parse_mode="MarkdownV2",
    )

async def handle_bot_current_version(query) -> None:
    """Handle bot current version display"""
    text = f"""📦 Bot Version Information

🏷️ Current Version: {__version__}
🐍 Python Version: {sys.version.split()[0]}
📅 Build Date: {datetime.now().strftime('%Y-%m-%d')}
🔧 Service: {SERVICE_NAME}

✅ Bot is running normally"""
    
    await query.edit_message_text(
        escape_markdown_v2(text),
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
        ]),
        parse_mode="MarkdownV2"
    )

async def handle_node_quick_update(query) -> None:
    """Handle quick update to latest version"""
    loading_msg = """🚀 Quick Update to Latest

⏳ Checking latest version...
⏳ Preparing update...

Please wait..."""
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        # Get latest version
        available_versions = await monitor.fetch_available_versions()
        if not available_versions:
            text = "❌ Cannot fetch latest version from Docker Hub"
            await query.edit_message_text(
                escape_markdown_v2(text),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
                ]),
                parse_mode="MarkdownV2"
            )
            return
        
        latest_version = available_versions[0]
        current_version = await monitor.get_node_current_version()
        
        # Check if already latest
        if current_version == latest_version:
            text = f"""✅ Already Latest Version

📦 Current Version: {current_version}
🆕 Latest Version: {latest_version}

Your node is already running the latest version."""
            
            await query.edit_message_text(
                escape_markdown_v2(text),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
                ]),
                parse_mode="MarkdownV2"
            )
            return
        
        # Proceed with update
        await handle_node_update_execute(query, latest_version)
        
    except Exception as e:
        error_text = f"❌ Error in quick update: {str(e)}"
        await query.edit_message_text(
            escape_markdown_v2(error_text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="node_management")]
            ]),
            parse_mode="MarkdownV2"
        )


async def handle_status(query) -> None:
    """Handle service status display"""
    loading_msg = "🔍 Checking service status...\n⏳ Please wait..."
    await query.edit_message_text(loading_msg, reply_markup=None)
    
    try:
        status = await monitor.get_service_status()
        
        active_icon = "🟢" if status["active"] else "🔴"
        enabled_icon = "🟢" if status["enabled"] else "🔴"
        
        text = f"""📊 Service Status Report

{active_icon} Active: {'Running' if status['active'] else 'Stopped'}
{enabled_icon} Enabled: {'Yes' if status['enabled'] else 'No'}
🏷️ Service: {SERVICE_NAME}

Status Details:
{status['status_output'][:500]}"""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh", callback_data="status")],
                [InlineKeyboardButton("🔙 Back", callback_data="system_menu")]
            ]),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error checking service status: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="system_menu")]
            ])
        )

async def handle_resources(query) -> None:
    """Handle system resources display"""
    try:
        resources = monitor.get_system_resources()
        
        cpu_icon = "🟢" if resources["cpu"]["percent"] < 70 else "🟡" if resources["cpu"]["percent"] < 90 else "🔴"
        mem_icon = "🟢" if resources["memory"]["percent"] < 70 else "🟡" if resources["memory"]["percent"] < 90 else "🔴"
        disk_icon = "🟢" if resources["disk"]["percent"] < 80 else "🟡" if resources["disk"]["percent"] < 95 else "🔴"
        
        text = f"""💻 System Resources

{cpu_icon} CPU Usage: {resources['cpu']['percent']:.1f}%
Cores: {resources['cpu']['cores']}

{mem_icon} Memory Usage: {resources['memory']['percent']:.1f}%
Used: {monitor.format_bytes(resources['memory']['used'])}
Available: {monitor.format_bytes(resources['memory']['available'])}
Total: {monitor.format_bytes(resources['memory']['total'])}

{disk_icon} Disk Usage: {resources['disk']['percent']:.1f}%
Used: {monitor.format_bytes(resources['disk']['used'])}
Free: {monitor.format_bytes(resources['disk']['free'])}
Total: {monitor.format_bytes(resources['disk']['total'])}"""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh", callback_data="resources")],
                [InlineKeyboardButton("🔙 Back", callback_data="system_menu")]
            ]),
            parse_mode="MarkdownV2"
        )
        
    except Exception as e:
        error_text = f"❌ Error getting system resources: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="system_menu")]
            ])
        )

async def handle_bot_stats(query) -> None:
    """Handle bot statistics display"""
    try:
        # Gather statistics
        uptime = time.time() - start_time if 'start_time' in globals() else 0
        uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m"
        
        # Escape all text properly for MarkdownV2
        stats_text = f"""📊 Bot Statistics

⏰ Uptime: {uptime_str}
🔍 Monitor Status: {'🟢 Active' if monitor.monitoring_active else '🔴 Inactive'}
👥 Authorized Users: {len(AUTHORIZED_USERS)}
📦 Version: {__version__}
🐳 Service: {SERVICE_NAME}
📝 Log Lines: {LOG_LINES}

🎯 Monitoring Features:
• Miss rate alerts
• System resource monitoring
• Peer connectivity checks
• RPC health validation"""
        
        # Escape the entire text for MarkdownV2
        escaped_text = escape_markdown_v2(stats_text)
        
        await query.edit_message_text(
            escaped_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
            ]),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        # Fallback to plain text if markdown fails
        error_text = f"❌ Error getting statistics: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="settings_menu")]
            ])
        )

async def handle_toggle_monitor(query) -> None:
    """Handle monitor toggle"""
    if monitor.monitoring_active:
        monitor.stop_monitoring()
        status_text = "🔴 Monitoring Stopped"
        message = "Automatic monitoring has been disabled."
    else:
        monitor.start_monitoring(300)
        status_text = "🟢 Monitoring Started"
        message = "Automatic monitoring is now active with 5-minute intervals."
    
    text = f"""📊 Monitor Status Changed

{status_text}

{message}"""
    
    escaped_text = escape_markdown_v2(text)
    
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
        ]),
        parse_mode="MarkdownV2"
    )

async def handle_monitor_intervals(query) -> None:
    """Handle monitor interval selection"""
    text = """⏱️ Monitor Intervals

Select monitoring check interval:"""
    
    intervals_menu = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("1 min", callback_data="interval_60"),
            InlineKeyboardButton("5 min", callback_data="interval_300"),
        ],
        [
            InlineKeyboardButton("10 min", callback_data="interval_600"),
            InlineKeyboardButton("30 min", callback_data="interval_1800"),
        ],
        [
            InlineKeyboardButton("1 hour", callback_data="interval_3600"),
            InlineKeyboardButton("Custom", callback_data="monitor_custom"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
    ])
    
    await query.edit_message_text(
        escape_markdown_v2(text),
        reply_markup=intervals_menu,
        parse_mode="MarkdownV2"
    )

async def handle_set_interval(query, interval: int) -> None:
    """Handle setting specific monitoring interval"""
    try:
        if monitor.monitoring_active:
            monitor.stop_monitoring()
        
        monitor.start_monitoring(interval)
        
        interval_text = f"{interval//60} minutes" if interval >= 60 else f"{interval} seconds"
        
        text = f"""✅ Monitoring Interval Updated

⏱️ New Interval: {interval_text}
🔍 Miss Rate Alert: > 30%
🔕 Alert Cooldown: 30 minutes

Monitoring has been restarted with the new interval."""
        
        await query.edit_message_text(
            escape_markdown_v2(text),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
            ]),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        error_text = f"❌ Error setting interval: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
            ])
        )


async def handle_set_interval(query, interval: int) -> None:
    """Handle setting monitor interval"""
    if monitor.monitoring_active:
        monitor.stop_monitoring()
    
    monitor.start_monitoring(interval)
    
    interval_text = f"{interval // 60} minute{'s' if interval > 60 else ''}"
    
    text = f"""✅ Interval Updated

⏱️ New interval: {interval_text}
🔍 Monitoring: 🟢 Active

The monitoring system has been restarted with the new interval."""
    
    escaped_text = escape_markdown_v2(text)
    
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
        ]),
        parse_mode="MarkdownV2"
    )

async def handle_notification_settings(query) -> None:
    """Handle notification settings"""
    text = """🔔 Notification Settings

Current notification settings:
• Platform: Telegram
• Miss rate threshold: > 30%
• Cooldown: 30 minutes
• Test alerts: Available

Notifications are automatically sent when validator miss rate exceeds the threshold."""
    
    escaped_text = escape_markdown_v2(text)
    
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔔 Test Alert", callback_data="test_alert")],
            [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
        ]),
        parse_mode="MarkdownV2"
    )

async def handle_log_settings(query) -> None:
    """Handle log settings"""
    text = """📊 Log Settings

Current log configuration:
• Log lines: 50
• Levels: ALL (DEBUG, INFO, WARN, ERROR, FATAL)
• Components: ALL available
• ANSI colors: Supported
• Clean view: Available

Log settings are optimized for comprehensive monitoring."""
    
    escaped_text = escape_markdown_v2(text)
    
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📝 View Logs", callback_data="logs_menu")],
            [InlineKeyboardButton("🔙 Back", callback_data="bot_settings")]
        ]),
        parse_mode="MarkdownV2"
    )


async def handle_version_info(query) -> None:
    """Handle version info display"""
    loading_msg = "🔍 Checking version information...\n⏳ Please wait..."
    await query.edit_message_text(loading_msg, reply_markup=None)
    try:
        remote_version = await monitor.get_remote_version()
        if not remote_version:
            remote_version = await monitor.get_bot_remote_version()
        current_parsed = parse_version(__version__)
        remote_parsed = parse_version(remote_version) if remote_version else None
        status = "🟢 Up to date"
        update_available = False
        if remote_parsed and remote_parsed > current_parsed:
            status = "🟡 Update available"
            update_available = True
        elif not remote_version:
            status = "🔴 Cannot check remote"
        version_text = f"""📦 Version Information
        🏷️ Current Version: {__version__}
🌐 Remote Version: {remote_version or 'Unknown'}
📊 Status: {status}

⏰ Last Check: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"""
        buttons = []
        if update_available:
            buttons.append([
                InlineKeyboardButton("🔄 Update Now", callback_data="apply_update"),
                InlineKeyboardButton("🔍 Check Again", callback_data="version_info")
            ])
        else:
            buttons.append([
                InlineKeyboardButton("🔍 Check Again", callback_data="version_info")
            ])
        buttons.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
        reply_markup = InlineKeyboardMarkup(buttons)
        escaped_text = escape_markdown_v2(version_text)
        await query.edit_message_text(
            escaped_text,
            reply_markup=reply_markup,
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        error_text = f"❌ Error checking version: {str(e)}"
        await query.edit_message_text(
            error_text,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
async def handle_refresh_system(query) -> None:
    """Handle comprehensive system refresh"""
    loading_msg = """🔄 *System Refresh*

⏳ Checking service status
⏳ Gathering system resources
⏳ Validating sync status
⏳ Checking peer connectivity

Please wait"""
    await query.edit_message_text(loading_msg, parse_mode="MarkdownV2")
    try:
        service_status = await monitor.get_service_status()
        resources = monitor.get_system_resources()
        sync_status = await monitor.get_sync_status()
        peer_status = await monitor.get_peer_status()
        service_icon = "🟢" if service_status["active"] else "🔴"
        cpu_icon = "🟢" if resources["cpu"]["percent"] < 70 else "🟡" if resources["cpu"]["percent"] < 90 else "🔴"
        sync_icon = "🟢" if sync_status.get("synced") else "🔴"
        peer_icon = "🟢" if peer_status.get("peer_found") else "🔴"
        summary_text = f"""✅ *System Refresh Complete*

📊 *Quick Status Overview:*

{service_icon} Service: {'Running' if service_status['active'] else 'Stopped'}
{cpu_icon} CPU: {resources['cpu']['percent']:.1f}%
{sync_icon} Sync: {'Synced' if sync_status.get('synced') else 'Syncing'}
{peer_icon} Peer: {'Connected' if peer_status.get('peer_found') else 'Not Found'}

⏰ Updated: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

Select a component for detailed information:"""
        await query.edit_message_text(
            summary_text,
            reply_markup=create_system_menu(),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        error_text = f"❌ *Refresh Error*\n\n{escape_markdown_v2(str(e))}"
        await query.edit_message_text(
            error_text,
            reply_markup=create_system_menu(),
            parse_mode="MarkdownV2"
        )
def create_bot_settings_menu() -> InlineKeyboardMarkup:
    """Create bot configuration submenu"""
    monitor_status = "🟢 Active" if monitor.monitoring_active else "🔴 Inactive"
    
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"📊 Monitor: {monitor_status}", callback_data="toggle_monitor"),
            InlineKeyboardButton("⏱️ Intervals", callback_data="monitor_intervals"),
        ],
        [
            InlineKeyboardButton("🔔 Notifications", callback_data="notification_settings"),
            InlineKeyboardButton("📊 Log Levels", callback_data="log_settings"),
        ],
        [
            InlineKeyboardButton("🔙 Back", callback_data="settings_menu")
        ]
    ])

async def handle_bot_settings(query) -> None:
    """Handle bot settings menu"""
    text = """⚙️ Bot Configuration

Configure monitoring, notifications, and logging preferences

Current Settings:
• Monitor Status: """ + ("🟢 Active" if monitor.monitoring_active else "🔴 Inactive") + """
• Check Interval: 300 seconds
• Alert Threshold: > 30% miss rate
• Log Level: INFO

Select an option:"""
    
    # Escape the entire text
    escaped_text = escape_markdown_v2(text)
    
    await query.edit_message_text(
        escaped_text,
        reply_markup=create_bot_settings_menu(),
        parse_mode="MarkdownV2"
    )
async def handle_apply_update(query, context) -> None:
    """Handle update application"""
    updating_msg = """🔄 Applying Update...

⏳ Downloading new version...
⏳ Creating backup...
⏳ Applying changes...

Please wait, do not close the bot..."""
    await query.edit_message_text(updating_msg, reply_markup=None)
    try:
        result = await monitor.check_for_updates()
        if result.get("update_available"):
            current_ver = result["current_version"]
            remote_ver = result["remote_version"]
            success = await monitor.apply_update(result["remote_content"], remote_ver)
            if success:
                final_msg = f"""✅ Update Successful!

📦 Updated: v{current_ver} → v{remote_ver}
🔄 Bot will restart in 3 seconds...

Thank you for keeping your bot updated!"""
                escaped_msg = escape_markdown_v2(final_msg)
                await query.edit_message_text(escaped_msg, parse_mode="MarkdownV2")
                await asyncio.sleep(3)
                logger.info(f"Restarting bot after update to v{remote_ver}")
                os.execv(sys.executable, [sys.executable] + sys.argv)
            else:
                error_msg = """❌ Update Failed

The update process encountered an error.
Your bot is still running the previous version.
Check logs for more details."""
                await query.edit_message_text(
                    error_msg,
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
                    ])
                )
        else:
            await query.edit_message_text(
                "❌ No update available",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
                ])
            )
    except Exception as e:
        error_msg = f"❌ Update error: {str(e)}"
        await query.edit_message_text(
            error_msg,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
async def handle_monitor_menu(query) -> None:
    """Handle monitor menu display"""
    status = "🟢 Active" if monitor.monitoring_active else "🔴 Inactive"
    
    menu_text = f"""📊 Monitoring Control Panel

🔍 Status: {status}
⚠️ Alert Threshold: > 30% miss rate
🔕 Cooldown: 30 minutes
📱 Notifications: Telegram

Select an option below:"""
    escaped_text = escape_markdown_v2(menu_text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=create_monitor_menu(),
        parse_mode="MarkdownV2"
    )
async def handle_monitor_status(query) -> None:
    """Handle monitor status display"""
    status = "🟢 Active" if monitor.monitoring_active else "🔴 Inactive"
    
    status_text = f"""📊 Monitoring Status Report

🔍 Status: {status}
⚠️ Alert Threshold: > 30% miss rate
🔕 Cooldown: 30 minutes
📱 Notifications: Telegram
⏰ Last Check: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}

🎯 Monitoring Features:
• Automatic miss rate detection
• Real-time Telegram alerts
• Configurable check intervals
• Smart cooldown system"""
    escaped_text = escape_markdown_v2(status_text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
        ]),
        parse_mode="MarkdownV2"
    )                                
async def handle_start_monitor(query, context) -> None:
    """Handle start monitoring"""
    if monitor.monitoring_active:
        await query.edit_message_text(
            "⚠️ Monitoring is already active!",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
            ])
        )
        return
    monitor.start_monitoring(300)
    
    success_text = """✅ Monitoring Started!

🔍 Miss Rate Alert: > 30%
⏱️ Check Interval: 300 seconds (5 minutes)
🔕 Alert Cooldown: 30 minutes
📱 Notification: Telegram

The bot will now automatically monitor your validator's miss rate."""
    
    escaped_text = escape_markdown_v2(success_text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
        ]),
        parse_mode="MarkdownV2"
    )
async def handle_stop_monitor(query) -> None:
    """Handle stop monitoring"""
    if not monitor.monitoring_active:
        await query.edit_message_text(
            "⚠️ Monitoring is not active!",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
            ])
        )
        return
    
    monitor.stop_monitoring()
    
    stop_text = """🛑 Monitoring Stopped

Automatic miss rate monitoring has been disabled.
You can restart it anytime from the monitor menu."""
    
    escaped_text = escape_markdown_v2(stop_text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
        ]),
        parse_mode="MarkdownV2"
    )

async def handle_monitor_custom(query, context) -> None:
    """Handle custom monitor interval setup"""
    text = """⚙️ Custom Monitor Interval

Enter the monitoring interval in seconds.

Examples:
• `60` - Check every 1 minute
• `300` - Check every 5 minutes (default)
• `600` - Check every 10 minutes
• `1800` - Check every 30 minutes

Minimum interval: 60 seconds
Please enter interval in seconds:"""
    
    escaped_text = escape_markdown_v2(text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
        ]),
        parse_mode="MarkdownV2"
    )
    context.user_data["awaiting_monitor_interval"] = True

async def handle_test_alert(query) -> None:
    """Handle test alert"""
    test_msg = """🔔 Sending Test Alert...

This will send a test notification to verify your alert system is working correctly."""
    
    await query.edit_message_text(test_msg, reply_markup=None)
    
    # Create a test alert
    test_alert_data = {
        "alert": True,
        "miss_rate": 35.5,
        "total_attestations": 100,
        "missed_attestations": 35,
        "validator_data": {
            "index": "TEST",
            "address": "0x1234567890abcdef1234567890abcdef12345678"
        }
    }
    
    success = await monitor.send_miss_rate_alert(test_alert_data)
    
    if success:
        result_text = """✅ Test Alert Sent Successfully!

Check your Telegram for the test alert message.
If you received it, your monitoring system is working correctly."""
    else:
        result_text = """❌ Test Alert Failed

There was an issue sending the test alert.
Please check your bot configuration and try again."""
    
    escaped_text = escape_markdown_v2(result_text)
    await query.edit_message_text(
        escaped_text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="monitor_menu")]
        ]),
        parse_mode="MarkdownV2"
    )        
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
        text = re.sub(r"\b(?:\d{1,3}){3}\d{1,3}\b", "[IP]", text)
        text = re.sub(r"\b(?:\d{1,3}){3}\d{1,3}:\d+\b", "[IP:PORT]", text)
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
    """Escape special characters for Telegram MarkdownV2"""
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text


async def handle_logs_menu(
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

def main():
    """Main function"""
    global start_time
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
    logger.info("Enhanced Aztec Monitor Bot started with automatic monitoring...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()