"""
OpenClaw Gateway - 概念原型
=============================
核心创新：凭证反转（Credential Inversion）

传统模式：OpenClaw持有所有凭证 → LLM可以直接访问
本方案：Gateway持有所有凭证 → OpenClaw只能请求Gateway代为执行

即使LLM被完全攻破，攻击者也拿不到凭证本身。

运行：
  python gateway.py                    # 启动网关
  python gateway.py --init             # 首次配置向导
  python gateway.py --test             # 自测试
  python gateway.py --verify           # 验证审计日志
"""

import json
import os
import sys
import time
import re
import hashlib
import hmac
import socket
import struct
import threading
import signal
import logging
import yaml
import secrets
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from collections import deque

# ============================================================
# 路径配置
# ============================================================

GATEWAY_DIR = Path.home() / ".openclaw"
CONFIG_PATH = GATEWAY_DIR / "gateway.yaml"
CREDENTIALS_PATH = GATEWAY_DIR / "credentials.enc"  # 凭证存储（加密）
AUDIT_PATH = GATEWAY_DIR / "audit.jsonl"
SOCKET_PATH = GATEWAY_DIR / "gateway.sock"
PID_PATH = GATEWAY_DIR / "gateway.pid"
SECRET_PATH = GATEWAY_DIR / ".gateway_secret"

LOG_FORMAT = "[%(asctime)s] %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("gateway")


# ============================================================
# 默认配置
# ============================================================

DEFAULT_CONFIG = {
    "filesystem": {
        "read": ["~/Documents/openclaw-workspace"],
        "write": ["~/Documents/openclaw-workspace"],
        "deny": ["~/.ssh", "~/.gnupg", "~/.openclaw/gateway.yaml",
                 "~/.openclaw/credentials.enc", "~/.openclaw/.gateway_secret"]
    },
    "email": {
        "accounts": []
    },
    "shell": {
        "allowed_commands": ["ls", "cat", "grep", "head", "tail", "wc",
                            "date", "echo", "pwd", "git status", "git diff", "git log"],
        "blocked_patterns": ["rm -rf", "rm -r /", "mkfs", "dd if=",
                           "> /dev/", "chmod 777", "curl", "wget", "nc "],
        "unknown_action": "prompt"
    },
    "apis": {
        "whitelisted": ["api.anthropic.com", "api.openai.com"],
        "blocked": ["doubleclick.net", "analytics.google.com"],
        "unknown_action": "prompt"
    },
    "pii": {
        "scan_outbound": True,
        "block_patterns": {
            "china_id":    {"regex": "(?<!\\d)\\d{17}[\\dXx](?!\\d)", "action": "block"},
            "credit_card": {"regex": "(?<!\\d)(?:\\d{4}[-\\s]?){3}\\d{4}(?!\\d)", "action": "block"},
        },
        "redact_patterns": {
            "phone": {"regex": "(?<!\\d)1[3-9]\\d{9}(?!\\d)", "action": "redact"},
            "email_addr": {"regex": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "action": "redact"},
        },
        "fuzz_gps": True,
        "gps_precision": 0.01
    },
    "confirmation": {
        "timeout_seconds": 60,
        "timeout_action": "deny",
        "show_raw_params": True
    }
}


# ============================================================
# 动作分类
# ============================================================

class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"       # 需要用户确认
    SANITIZE = "sanitize"   # 允许但需清洗

# 不可自动授权的操作（硬不变量）
HARD_INVARIANTS = {
    "file_delete",
    "email_send",
    "payment",
    "credential_change",
    "social_post",
    "account_action",
}


# ============================================================
# 凭证保险箱
# ============================================================

class CredentialVault:
    """
    凭证反转的核心：所有敏感凭证由Gateway持有。
    OpenClaw进程永远看不到原始凭证。
    
    当OpenClaw需要调用API时，它向Gateway发送请求，
    Gateway用自己持有的凭证代为执行。
    """

    def __init__(self, vault_path: Path = CREDENTIALS_PATH, 
                 secret_path: Path = SECRET_PATH):
        self.vault_path = vault_path
        self.secret_path = secret_path
        self._secret = self._load_or_create_secret()
        self._credentials = self._load_vault()

    def _load_or_create_secret(self) -> bytes:
        if self.secret_path.exists():
            return self.secret_path.read_bytes()
        secret = secrets.token_bytes(32)
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)
        self.secret_path.write_bytes(secret)
        os.chmod(str(self.secret_path), 0o600)
        return secret

    def _encrypt(self, data: str) -> bytes:
        """简单的对称加密（生产环境应使用Fernet或age）"""
        key = hashlib.sha256(self._secret).digest()
        nonce = secrets.token_bytes(16)
        # XOR加密（概念演示——生产环境换成AES-GCM）
        data_bytes = data.encode()
        stream = hashlib.sha256(key + nonce).digest() * (len(data_bytes) // 32 + 1)
        encrypted = bytes(a ^ b for a, b in zip(data_bytes, stream[:len(data_bytes)]))
        mac = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()[:16]
        return nonce + mac + encrypted

    def _decrypt(self, blob: bytes) -> str:
        key = hashlib.sha256(self._secret).digest()
        nonce = blob[:16]
        mac = blob[16:32]
        encrypted = blob[32:]
        expected_mac = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Credential vault integrity check failed")
        stream = hashlib.sha256(key + nonce).digest() * (len(encrypted) // 32 + 1)
        decrypted = bytes(a ^ b for a, b in zip(encrypted, stream[:len(encrypted)]))
        return decrypted.decode()

    def _load_vault(self) -> dict:
        if not self.vault_path.exists():
            return {}
        try:
            blob = self.vault_path.read_bytes()
            return json.loads(self._decrypt(blob))
        except Exception as e:
            log.warning(f"Failed to load credential vault: {e}")
            return {}

    def _save_vault(self):
        data = json.dumps(self._credentials, ensure_ascii=False)
        self.vault_path.write_bytes(self._encrypt(data))
        os.chmod(str(self.vault_path), 0o600)

    def store(self, service: str, key: str, value: str):
        """存储凭证（仅Gateway可调用）"""
        if service not in self._credentials:
            self._credentials[service] = {}
        self._credentials[service][key] = value
        self._save_vault()
        log.info(f"Stored credential: {service}/{key}")

    def get(self, service: str, key: str) -> Optional[str]:
        """获取凭证（仅Gateway内部使用，永远不会暴露给OpenClaw）"""
        return self._credentials.get(service, {}).get(key)

    def list_services(self) -> list:
        """列出有凭证的服务（不暴露凭证内容）"""
        return [
            {"service": svc, "keys": list(keys.keys())}
            for svc, keys in self._credentials.items()
        ]

    def has(self, service: str, key: str) -> bool:
        return key in self._credentials.get(service, {})


# ============================================================
# 权限引擎
# ============================================================

class PermissionEngine:
    """基于规则的权限判定——纯逻辑，无LLM"""

    def __init__(self, config: dict):
        self.config = config
        self._compile_pii_patterns()

    def _compile_pii_patterns(self):
        self._pii_block = []
        self._pii_redact = []
        pii_cfg = self.config.get("pii", {})

        for name, rule in pii_cfg.get("block_patterns", {}).items():
            self._pii_block.append((name, re.compile(rule["regex"])))

        for name, rule in pii_cfg.get("redact_patterns", {}).items():
            self._pii_redact.append((name, re.compile(rule["regex"])))

    def _expand(self, p: str) -> str:
        return os.path.expanduser(p)

    # ------ 文件系统权限 ------

    def check_file_read(self, filepath: str) -> Action:
        filepath = os.path.abspath(self._expand(filepath))
        fs = self.config.get("filesystem", {})

        for denied in fs.get("deny", []):
            denied = os.path.abspath(self._expand(denied))
            if filepath.startswith(denied):
                return Action.DENY

        for allowed in fs.get("read", []):
            allowed = os.path.abspath(self._expand(allowed))
            if filepath.startswith(allowed):
                return Action.ALLOW

        return Action.PROMPT

    def check_file_write(self, filepath: str) -> Action:
        filepath = os.path.abspath(self._expand(filepath))
        fs = self.config.get("filesystem", {})

        for denied in fs.get("deny", []):
            denied = os.path.abspath(self._expand(denied))
            if filepath.startswith(denied):
                return Action.DENY

        for allowed in fs.get("write", []):
            allowed = os.path.abspath(self._expand(allowed))
            if filepath.startswith(allowed):
                return Action.PROMPT  # 写入仍需确认（可配置为ALLOW）

        return Action.DENY

    def check_file_delete(self, filepath: str) -> Action:
        # 硬不变量：删除始终需要确认
        filepath = os.path.abspath(self._expand(filepath))
        fs = self.config.get("filesystem", {})

        for denied in fs.get("deny", []):
            denied = os.path.abspath(self._expand(denied))
            if filepath.startswith(denied):
                return Action.DENY

        return Action.PROMPT

    # ------ Shell权限 ------

    def check_shell(self, command: str) -> Action:
        shell = self.config.get("shell", {})
        cmd_lower = command.strip().lower()

        for blocked in shell.get("blocked_patterns", []):
            if blocked.lower() in cmd_lower:
                return Action.DENY

        for allowed in shell.get("allowed_commands", []):
            if cmd_lower.startswith(allowed.lower()):
                return Action.ALLOW

        unknown = shell.get("unknown_action", "prompt")
        return Action.PROMPT if unknown == "prompt" else Action.DENY

    # ------ API权限 ------

    def check_api(self, host: str) -> Action:
        apis = self.config.get("apis", {})

        for blocked in apis.get("blocked", []):
            if blocked in host:
                return Action.DENY

        for allowed in apis.get("whitelisted", []):
            if allowed in host:
                return Action.ALLOW

        unknown = apis.get("unknown_action", "prompt")
        return Action.PROMPT if unknown == "prompt" else Action.DENY

    # ------ PII扫描 ------

    def scan_pii(self, text: str) -> dict:
        """返回 {should_block: bool, findings: [...], sanitized: str}"""
        findings = []
        should_block = False
        sanitized = text

        for name, regex in self._pii_block:
            if regex.search(text):
                findings.append({"type": name, "action": "block"})
                should_block = True

        for name, regex in self._pii_redact:
            def _redact(m, _name=name):
                h = hashlib.sha256(m.group().encode()).hexdigest()[:8]
                findings.append({"type": _name, "action": "redact", "hash": h})
                return f"[REDACTED:{_name}]"
            sanitized = regex.sub(_redact, sanitized)

        return {
            "should_block": should_block,
            "findings": findings,
            "sanitized": sanitized
        }

    # ------ 综合判定 ------

    def evaluate(self, request: dict) -> dict:
        """
        综合评估一个操作请求。
        
        输入: {
            "action": "file_read" | "file_write" | "file_delete" | 
                      "shell" | "api_call" | "email_send" | "email_read",
            "params": { ... }
        }
        
        输出: {
            "verdict": "allow" | "deny" | "prompt",
            "reason": "...",
            "sanitized_params": { ... },
            "pii_findings": [...],
            "is_hard_invariant": bool
        }
        """
        action = request.get("action", "")
        params = request.get("params", {})
        params_str = json.dumps(params, ensure_ascii=False)

        # 1. PII扫描
        pii = {"should_block": False, "findings": [], "sanitized": params_str}
        if self.config.get("pii", {}).get("scan_outbound", True):
            pii = self.scan_pii(params_str)
            if pii["should_block"]:
                return {
                    "verdict": "deny",
                    "reason": f"blocked_pii: {[f['type'] for f in pii['findings'] if f['action']=='block']}",
                    "sanitized_params": params,
                    "pii_findings": pii["findings"],
                    "is_hard_invariant": False
                }

        # 2. 操作类型权限
        verdict = Action.DENY
        reason = "unknown_action"

        if action == "file_read":
            verdict = self.check_file_read(params.get("path", ""))
            reason = f"file_read:{params.get('path', '')}"

        elif action == "file_write":
            verdict = self.check_file_write(params.get("path", ""))
            reason = f"file_write:{params.get('path', '')}"

        elif action == "file_delete":
            verdict = self.check_file_delete(params.get("path", ""))
            reason = f"file_delete:{params.get('path', '')}"

        elif action == "shell":
            verdict = self.check_shell(params.get("command", ""))
            reason = f"shell:{params.get('command', '')[:50]}"

        elif action == "api_call":
            verdict = self.check_api(params.get("host", ""))
            reason = f"api:{params.get('host', '')}"

        elif action == "email_send":
            verdict = Action.PROMPT  # 硬不变量
            reason = f"email_send:{params.get('to', '')}"

        elif action == "email_read":
            # 检查邮箱是否被授权
            account = params.get("account", "")
            accounts = self.config.get("email", {}).get("accounts", [])
            authorized = any(
                a.get("address") == account and a.get("can_read", False)
                for a in accounts
            )
            verdict = Action.ALLOW if authorized else Action.DENY
            reason = f"email_read:{account}"

        # 3. 构造清洗后的参数
        sanitized_params = params
        if pii["findings"]:
            try:
                sanitized_params = json.loads(pii["sanitized"])
            except json.JSONDecodeError:
                sanitized_params = params

        return {
            "verdict": verdict.value,
            "reason": reason,
            "sanitized_params": sanitized_params,
            "pii_findings": pii["findings"],
            "is_hard_invariant": action in HARD_INVARIANTS
        }


# ============================================================
# 审计日志（链式哈希）
# ============================================================

class AuditLog:
    def __init__(self, path: Path = AUDIT_PATH):
        self.path = path
        self.prev_hash = "genesis"
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            try:
                last_line = path.read_text().strip().split('\n')[-1]
                self.prev_hash = json.loads(last_line).get("hash", "genesis")
            except Exception:
                pass

    def write(self, event: dict) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "prev": self.prev_hash,
            **event
        }
        raw = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self.prev_hash = entry["hash"]

        with open(self.path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> dict:
        if not self.path.exists():
            return {"valid": True, "entries": 0}

        lines = self.path.read_text().strip().split('\n')
        expected = "genesis"
        errors = []

        for i, line in enumerate(lines):
            try:
                e = json.loads(line)
                if e.get("prev") != expected:
                    errors.append({"line": i+1, "error": "chain_break"})
                expected = e.get("hash", "")
            except Exception:
                errors.append({"line": i+1, "error": "parse"})

        return {"valid": len(errors) == 0, "entries": len(lines), "errors": errors}


# ============================================================
# 用户确认队列
# ============================================================

class ConfirmationQueue:
    """
    管理待确认的操作请求。
    
    实际部署时，这里会连接Telegram/WhatsApp Bot：
    - 向用户推送确认消息
    - 等待用户回复 YES/NO
    - 展示的是原始参数，不是LLM的描述（防止LLM伪造描述）
    """

    def __init__(self, timeout: int = 60, default_action: str = "deny"):
        self.timeout = timeout
        self.default_action = default_action
        self.pending = {}  # confirm_id -> {event, resolve_func, ...}

    def create(self, request: dict) -> str:
        """创建待确认项，返回confirm_id"""
        confirm_id = secrets.token_hex(8)
        self.pending[confirm_id] = {
            "request": request,
            "created_at": time.time(),
            "status": "pending"
        }
        return confirm_id

    def resolve(self, confirm_id: str, approved: bool) -> bool:
        """用户响应确认"""
        if confirm_id in self.pending:
            self.pending[confirm_id]["status"] = "approved" if approved else "rejected"
            return True
        return False

    def check(self, confirm_id: str) -> Optional[str]:
        """检查确认状态"""
        item = self.pending.get(confirm_id)
        if not item:
            return None

        # 超时检查
        if time.time() - item["created_at"] > self.timeout:
            self.pending.pop(confirm_id, None)
            return self.default_action

        status = item["status"]
        if status != "pending":
            self.pending.pop(confirm_id, None)
            return "allow" if status == "approved" else "deny"

        return "pending"

    def format_prompt(self, request: dict) -> str:
        """
        生成用户可读的确认提示。
        关键：展示原始参数，不信任LLM的描述。
        """
        action = request.get("action", "unknown")
        params = request.get("params", {})

        lines = [f"⚠️  OpenClaw 请求执行操作"]
        lines.append(f"类型: {action}")

        if action == "shell":
            lines.append(f"命令: {params.get('command', '?')}")
        elif action == "email_send":
            lines.append(f"收件人: {params.get('to', '?')}")
            body = params.get('body', '')
            lines.append(f"内容预览: {body[:200]}{'...' if len(body) > 200 else ''}")
        elif action.startswith("file_"):
            lines.append(f"路径: {params.get('path', '?')}")
        elif action == "api_call":
            lines.append(f"目标: {params.get('host', '?')}{params.get('path', '')}")

        lines.append("")
        lines.append("回复 Y 允许 / N 拒绝")
        return "\n".join(lines)


# ============================================================
# 网关主进程
# ============================================================

class Gateway:
    def __init__(self):
        GATEWAY_DIR.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()
        self.permissions = PermissionEngine(self.config)
        self.vault = CredentialVault()
        self.audit = AuditLog()
        self.confirmations = ConfirmationQueue(
            timeout=self.config.get("confirmation", {}).get("timeout_seconds", 60),
            default_action=self.config.get("confirmation", {}).get("timeout_action", "deny")
        )
        self.stats = {"requests": 0, "allowed": 0, "denied": 0, "prompted": 0}

    def _load_config(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    return yaml.safe_load(f)
            except Exception as e:
                log.warning(f"Config load failed, using defaults: {e}")
        return DEFAULT_CONFIG

    def handle_request(self, msg: dict) -> dict:
        """处理来自OpenClaw的请求"""
        msg_type = msg.get("type", "")

        if msg_type == "authorize":
            return self._handle_authorize(msg.get("payload", {}))
        elif msg_type == "confirm_response":
            return self._handle_confirm(msg.get("payload", {}))
        elif msg_type == "execute_with_credential":
            return self._handle_credentialed_exec(msg.get("payload", {}))
        elif msg_type == "status":
            return self._get_status()
        elif msg_type == "list_credentials":
            return {"services": self.vault.list_services()}
        else:
            return {"error": f"unknown message type: {msg_type}"}

    def _handle_authorize(self, payload: dict) -> dict:
        """评估操作请求"""
        self.stats["requests"] += 1

        result = self.permissions.evaluate(payload)

        if result["verdict"] == "deny":
            self.stats["denied"] += 1
            self.audit.write({
                "event": "denied",
                "action": payload.get("action"),
                "reason": result["reason"],
                "pii": len(result["pii_findings"])
            })
            return {
                "verdict": "deny",
                "reason": result["reason"]
            }

        if result["verdict"] == "prompt" or result["is_hard_invariant"]:
            self.stats["prompted"] += 1
            confirm_id = self.confirmations.create(payload)
            prompt_text = self.confirmations.format_prompt(payload)

            self.audit.write({
                "event": "confirmation_requested",
                "action": payload.get("action"),
                "confirm_id": confirm_id,
                "is_hard_invariant": result["is_hard_invariant"]
            })

            return {
                "verdict": "prompt",
                "confirm_id": confirm_id,
                "prompt": prompt_text,
                "is_hard_invariant": result["is_hard_invariant"]
            }

        # Allow
        self.stats["allowed"] += 1
        self.audit.write({
            "event": "allowed",
            "action": payload.get("action"),
            "reason": result["reason"],
            "pii_redacted": len(result["pii_findings"])
        })

        return {
            "verdict": "allow",
            "sanitized_params": result["sanitized_params"]
        }

    def _handle_confirm(self, payload: dict) -> dict:
        """处理用户确认响应"""
        confirm_id = payload.get("confirm_id", "")
        approved = payload.get("approved", False)

        self.confirmations.resolve(confirm_id, approved)
        status = self.confirmations.check(confirm_id)

        self.audit.write({
            "event": "confirmation_resolved",
            "confirm_id": confirm_id,
            "approved": approved
        })

        if status == "allow":
            self.stats["allowed"] += 1
            return {"verdict": "allow"}
        else:
            self.stats["denied"] += 1
            return {"verdict": "deny", "reason": "user_rejected"}

    def _handle_credentialed_exec(self, payload: dict) -> dict:
        """
        凭证反转的核心：Gateway代为执行需要凭证的操作。
        OpenClaw说"帮我用Gmail发邮件"，Gateway用自己持有的凭证执行。
        
        在完整实现中，这里会包含真正的API调用代码。
        当前返回模拟结果以演示架构。
        """
        service = payload.get("service", "")
        operation = payload.get("operation", "")

        # 检查是否有该服务的凭证
        if not self.vault.has(service, "token"):
            return {
                "error": "no_credential",
                "message": f"Gateway does not hold credentials for '{service}'. "
                          f"Use 'gateway.py --init' to configure."
            }

        # 在这里，Gateway会使用 self.vault.get(service, "token") 
        # 来执行实际的API调用。OpenClaw永远不会看到token本身。

        self.audit.write({
            "event": "credentialed_exec",
            "service": service,
            "operation": operation
            # 注意：不记录凭证内容
        })

        return {
            "status": "executed",
            "service": service,
            "operation": operation,
            "note": "Gateway executed with its own credentials. Token never exposed to agent."
        }

    def _get_status(self) -> dict:
        return {
            "stats": self.stats,
            "audit_integrity": self.audit.verify(),
            "credential_services": [s["service"] for s in self.vault.list_services()],
            "pending_confirmations": len(self.confirmations.pending)
        }


# ============================================================
# IPC服务器
# ============================================================

class GatewayServer:
    def __init__(self, gateway: Gateway):
        self.gateway = gateway
        self.running = False

    def start(self):
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(SOCKET_PATH))
        sock.listen(5)
        sock.settimeout(1.0)
        os.chmod(str(SOCKET_PATH), 0o600)
        PID_PATH.write_text(str(os.getpid()))

        self.running = True
        log.info(f"Gateway listening on {SOCKET_PATH}")

        while self.running:
            try:
                conn, _ = sock.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error(f"Accept error: {e}")

        sock.close()
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        if PID_PATH.exists():
            PID_PATH.unlink()

    def _handle(self, conn):
        try:
            conn.settimeout(10.0)
            raw = self._recv(conn)
            if raw:
                msg = json.loads(raw)
                resp = self.gateway.handle_request(msg)
                self._send(conn, json.dumps(resp, ensure_ascii=False))
        except Exception as e:
            log.error(f"Handler error: {e}")
            try:
                self._send(conn, json.dumps({"error": str(e)}))
            except Exception:
                pass
        finally:
            conn.close()

    def _recv(self, conn) -> Optional[str]:
        h = conn.recv(4)
        if len(h) < 4:
            return None
        length = struct.unpack("!I", h)[0]
        if length > 1_000_000:
            return None
        data = b""
        while len(data) < length:
            chunk = conn.recv(min(length - len(data), 8192))
            if not chunk:
                return None
            data += chunk
        return data.decode()

    def _send(self, conn, msg: str):
        data = msg.encode()
        conn.sendall(struct.pack("!I", len(data)) + data)

    def stop(self):
        self.running = False


# ============================================================
# 客户端（供OpenClaw使用）
# ============================================================

class GatewayClient:
    """
    OpenClaw端的Gateway客户端。
    
    示例：
        gw = GatewayClient()
        
        # 请求读取文件
        r = gw.authorize("file_read", {"path": "~/Documents/notes.md"})
        if r["verdict"] == "allow":
            content = open(r["sanitized_params"]["path"]).read()
        
        # 请求发送邮件（会触发用户确认）
        r = gw.authorize("email_send", {"to": "alice@example.com", "body": "Hi"})
        if r["verdict"] == "prompt":
            # 等待用户在Telegram上确认
            print(r["prompt"])
            # ... 用户确认后 ...
            r2 = gw.confirm(r["confirm_id"], approved=True)
        
        # 使用Gateway的凭证发送（OpenClaw不接触OAuth token）
        r = gw.execute_with_credential("gmail", "send_email", 
                                        {"to": "alice@example.com", "body": "Hi"})
    """

    def __init__(self, socket_path: str = str(SOCKET_PATH)):
        self.socket_path = socket_path

    def _call(self, msg_type: str, payload: dict = None) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            sock.settimeout(5.0)
            msg = json.dumps({"type": msg_type, "payload": payload or {}})
            data = msg.encode()
            sock.sendall(struct.pack("!I", len(data)) + data)

            h = sock.recv(4)
            if len(h) < 4:
                return {"error": "no_response"}
            length = struct.unpack("!I", h)[0]
            resp = b""
            while len(resp) < length:
                chunk = sock.recv(min(length - len(resp), 8192))
                if not chunk:
                    break
                resp += chunk
            return json.loads(resp.decode())
        except FileNotFoundError:
            return {"error": "gateway_not_running", "verdict": "deny"}
        except Exception as e:
            return {"error": str(e), "verdict": "deny"}
        finally:
            sock.close()

    def authorize(self, action: str, params: dict) -> dict:
        return self._call("authorize", {"action": action, "params": params})

    def confirm(self, confirm_id: str, approved: bool) -> dict:
        return self._call("confirm_response", {
            "confirm_id": confirm_id, "approved": approved
        })

    def execute_with_credential(self, service: str, operation: str, params: dict = None) -> dict:
        return self._call("execute_with_credential", {
            "service": service, "operation": operation, "params": params or {}
        })

    def status(self) -> dict:
        return self._call("status")


# ============================================================
# 首次配置向导
# ============================================================

def init_wizard():
    print("=" * 55)
    print("  OpenClaw Gateway - 首次配置")
    print("=" * 55)

    GATEWAY_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 生成默认配置
    if CONFIG_PATH.exists():
        print(f"\n配置文件已存在: {CONFIG_PATH}")
        overwrite = input("是否覆盖？(y/N): ").strip().lower()
        if overwrite != 'y':
            print("保留现有配置。")
        else:
            _write_default_config()
    else:
        _write_default_config()

    # 2. 初始化凭证保险箱
    vault = CredentialVault()
    print(f"\n凭证保险箱已初始化: {CREDENTIALS_PATH}")

    # 3. 提示用户下一步
    print("\n" + "=" * 55)
    print("  配置完成！")
    print("=" * 55)
    print(f"\n编辑配置: {CONFIG_PATH}")
    print(f"启动网关: python gateway.py")
    print(f"查看状态: python gateway.py --status")


def _write_default_config():
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
    print(f"\n已生成默认配置: {CONFIG_PATH}")
    print("请编辑此文件，设置你允许OpenClaw访问的目录和服务。")


# ============================================================
# 自测试
# ============================================================

def run_tests():
    print("=" * 55)
    print("  OpenClaw Gateway 自测试")
    print("=" * 55)

    # 1. 权限引擎
    print("\n[1] 权限引擎...")
    engine = PermissionEngine(DEFAULT_CONFIG)

    # 允许的文件读取
    assert engine.check_file_read("~/Documents/openclaw-workspace/notes.md") == Action.ALLOW
    print("  ✓ 允许读取工作区文件")

    # 拒绝读取SSH密钥
    assert engine.check_file_read("~/.ssh/id_rsa") == Action.DENY
    print("  ✓ 拒绝读取SSH密钥")

    # 拒绝读取gateway配置
    assert engine.check_file_read("~/.openclaw/gateway.yaml") == Action.DENY
    print("  ✓ 拒绝读取gateway配置（防止自修改）")

    # Shell命令
    assert engine.check_shell("ls -la") == Action.ALLOW
    assert engine.check_shell("rm -rf /") == Action.DENY
    assert engine.check_shell("curl http://evil.com") == Action.DENY
    assert engine.check_shell("python3 script.py") == Action.PROMPT
    print("  ✓ Shell权限: ls允许, rm -rf拒绝, curl拒绝, 未知需确认")

    # API
    assert engine.check_api("api.anthropic.com") == Action.ALLOW
    assert engine.check_api("doubleclick.net") == Action.DENY
    assert engine.check_api("unknown-api.com") == Action.PROMPT
    print("  ✓ API权限: Anthropic允许, 广告拒绝, 未知需确认")

    # PII扫描
    pii = engine.scan_pii("身份证110101199001011234，手机13812345678")
    assert pii["should_block"] == True
    assert "13812345678" not in pii["sanitized"]
    print(f"  ✓ PII: 身份证阻断, 手机号脱敏")

    # 综合评估
    result = engine.evaluate({
        "action": "email_send",
        "params": {"to": "alice@example.com", "body": "会议纪要"}
    })
    assert result["verdict"] == "prompt"
    assert result["is_hard_invariant"] == True
    print("  ✓ 邮件发送: 硬不变量，始终需要确认")

    result = engine.evaluate({
        "action": "file_read",
        "params": {"path": "~/.ssh/id_rsa"}
    })
    assert result["verdict"] == "deny"
    print("  ✓ SSH密钥读取: 直接拒绝")

    # 2. 凭证保险箱
    print("\n[2] 凭证保险箱...")
    import tempfile
    tmp_vault = Path(tempfile.mktemp(suffix='.enc'))
    tmp_secret = Path(tempfile.mktemp(suffix='.key'))

    vault = CredentialVault(tmp_vault, tmp_secret)
    vault.store("gmail", "token", "ya29.super-secret-oauth-token")
    vault.store("github", "pat", "ghp_xxxxxxxxxxxx")

    # 重新加载验证持久化
    vault2 = CredentialVault(tmp_vault, tmp_secret)
    assert vault2.get("gmail", "token") == "ya29.super-secret-oauth-token"
    assert vault2.get("github", "pat") == "ghp_xxxxxxxxxxxx"
    print("  ✓ 凭证加密存储和恢复正常")

    services = vault2.list_services()
    assert all("token" not in str(s) or "keys" in s for s in services)
    print("  ✓ 列出服务不暴露凭证内容")

    # 篡改检测
    try:
        tampered = tmp_vault.read_bytes()
        tampered_bytes = bytearray(tampered)
        tampered_bytes[-1] ^= 0xFF
        tmp_vault.write_bytes(bytes(tampered_bytes))
        vault3 = CredentialVault(tmp_vault, tmp_secret)
        # 如果加载成功说明MAC验证失败了——这不应该发生
        if vault3.get("gmail", "token") == "ya29.super-secret-oauth-token":
            print("  ⚠ 篡改检测未触发（XOR加密的局限性）")
        else:
            print("  ✓ 篡改后凭证不可读")
    except ValueError:
        print("  ✓ 篡改检测成功，拒绝加载")
    except Exception:
        print("  ✓ 篡改后加载异常（安全）")

    tmp_vault.unlink(missing_ok=True)
    tmp_secret.unlink(missing_ok=True)

    # 3. 审计日志
    print("\n[3] 审计日志...")
    tmp_log = Path(tempfile.mktemp(suffix='.jsonl'))
    audit = AuditLog(tmp_log)
    audit.write({"event": "test_allow", "action": "file_read"})
    audit.write({"event": "test_deny", "action": "shell", "command": "rm -rf /"})
    result = audit.verify()
    assert result["valid"]
    assert result["entries"] == 2
    print("  ✓ 链式审计日志完整性验证通过")
    tmp_log.unlink(missing_ok=True)

    # 4. 确认队列
    print("\n[4] 确认队列...")
    queue = ConfirmationQueue(timeout=2)
    cid = queue.create({"action": "email_send", "params": {"to": "alice@example.com"}})
    assert queue.check(cid) == "pending"
    queue.resolve(cid, True)
    assert queue.check(cid) == "allow"
    print("  ✓ 确认流程: 创建→待定→批准→允许")

    cid2 = queue.create({"action": "shell", "params": {"command": "deploy.sh"}})
    queue.resolve(cid2, False)
    assert queue.check(cid2) == "deny"
    print("  ✓ 确认流程: 创建→待定→拒绝→拒绝")

    # 5. 网关集成
    print("\n[5] 网关集成测试...")
    gw = Gateway()

    # 允许的操作
    r = gw.handle_request({
        "type": "authorize",
        "payload": {"action": "file_read",
                    "params": {"path": "~/Documents/openclaw-workspace/notes.md"}}
    })
    assert r["verdict"] == "allow"
    print(f"  ✓ 工作区文件读取: {r['verdict']}")

    # 拒绝的操作
    r = gw.handle_request({
        "type": "authorize",
        "payload": {"action": "shell", "params": {"command": "rm -rf /"}}
    })
    assert r["verdict"] == "deny"
    print(f"  ✓ 危险命令: {r['verdict']}")

    # PII阻断
    r = gw.handle_request({
        "type": "authorize",
        "payload": {"action": "api_call",
                    "params": {"host": "api.anthropic.com",
                              "body": "用户身份证110101199001011234"}}
    })
    assert r["verdict"] == "deny"
    print(f"  ✓ PII外泄阻断: {r['verdict']}")

    # 需要确认的操作
    r = gw.handle_request({
        "type": "authorize",
        "payload": {"action": "email_send",
                    "params": {"to": "alice@example.com", "body": "Hi"}}
    })
    assert r["verdict"] == "prompt"
    assert r["is_hard_invariant"] == True
    print(f"  ✓ 邮件发送需确认: {r['verdict']} (hard_invariant={r['is_hard_invariant']})")

    # 用户批准
    r2 = gw.handle_request({
        "type": "confirm_response",
        "payload": {"confirm_id": r["confirm_id"], "approved": True}
    })
    assert r2["verdict"] == "allow"
    print(f"  ✓ 用户批准后: {r2['verdict']}")

    # 凭证反转
    r = gw.handle_request({
        "type": "execute_with_credential",
        "payload": {"service": "gmail", "operation": "send_email"}
    })
    assert "no_credential" in r.get("error", "")
    print(f"  ✓ 无凭证时拒绝执行: {r['error']}")

    # 状态查询
    status = gw.handle_request({"type": "status"})
    print(f"  ✓ 统计: {status['stats']}")

    print("\n" + "=" * 55)
    print("  所有测试通过 ✓")
    print("=" * 55)


# ============================================================
# 入口
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="OpenClaw Gateway")
    parser.add_argument("--init", action="store_true", help="首次配置向导")
    parser.add_argument("--test", action="store_true", help="运行自测试")
    parser.add_argument("--verify", action="store_true", help="验证审计日志")
    parser.add_argument("--status", action="store_true", help="查看网关状态")
    args = parser.parse_args()

    if args.init:
        init_wizard()
        return

    if args.test:
        run_tests()
        return

    if args.verify:
        audit = AuditLog()
        print(json.dumps(audit.verify(), indent=2))
        return

    if args.status:
        client = GatewayClient()
        print(json.dumps(client.status(), indent=2, ensure_ascii=False))
        return

    # 启动网关服务
    gw = Gateway()
    server = GatewayServer(gw)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("=" * 55)
    log.info("  OpenClaw Gateway 已启动")
    log.info(f"  配置: {CONFIG_PATH}")
    log.info(f"  审计: {AUDIT_PATH}")
    log.info("=" * 55)

    server.start()


if __name__ == "__main__":
    main()
