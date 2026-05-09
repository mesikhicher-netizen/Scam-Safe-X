#!/usr/bin/env python3
"""
Scam SafeX Bot – Premium Telegram Scam Report Bot
Production-Ready: Secure, Stable, Thread-Safe, No Flood
"""

import os
import logging
import random
import re
import string
import time
import sys
import threading
import html as html_module
from datetime import datetime
from typing import Dict, Optional, Tuple, Any, List, Union
from functools import wraps

import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, AutoReconnect, PyMongoError
import telebot
from telebot import apihelper
from telebot.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton,
    CallbackQuery, Message
)

# ----------------------------- CONFIGURATION (ENVIRONMENT ONLY) -----------------
# Load from environment variables for security - NO DEFAULTS FOR SECRETS!
BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "scam_safex")
ADMIN_IDS_STR = os.getenv("ADMIN_IDS", "5665198013")
SCAM_CHANNEL = os.getenv("SCAM_CHANNEL", "@testingkruhu")
WELCOME_IMAGE = os.getenv("WELCOME_IMAGE", "https://i.postimg.cc/5yZKZXWg/file-000000002ba871fb90ff35abdb94ca34-(1).png")
OWNER_USERNAME = os.getenv("OWNER_USERNAME", "@raunak_portal")
SCAM_ALERT_IMAGE = os.getenv("SCAM_ALERT_IMAGE", "https://i.postimg.cc/7L7dDMZb/IMG-20260508-111219-227.jpg")
GROUP_CHAT_ID = int(os.getenv("GROUP_CHAT_ID", "0")) if os.getenv("GROUP_CHAT_ID") and os.getenv("GROUP_CHAT_ID").strip() else None

# Validate required secrets
if not BOT_TOKEN:
    raise ValueError("❌ BOT_TOKEN environment variable not set")
if not MONGO_URI:
    raise ValueError("❌ MONGO_URI environment variable not set")

ADMIN_IDS = [int(x.strip()) for x in ADMIN_IDS_STR.split(",") if x.strip()]

# ----------------------------- LOGGING --------------------------------------
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ----------------------------- BOT INIT -------------------------------------
bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
bot.threaded = False  # avoid threading conflicts with our own state lock

# ----------------------------- MONGO DB SETUP with RETRY --------------------
class MongoManager:
    def __init__(self, uri, db_name):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self.connect()

    def connect(self):
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self._ensure_indexes()
            logger.info("MongoDB connected")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"MongoDB connection failed: {e}")
            sys.exit(1)

    def _ensure_indexes(self):
        reports = self.db["reports"]
        reports.create_index("report_unique_id", unique=True)
        reports.create_index("scammer_username")
        reports.create_index("fake_profile")
        reports.create_index("reporter_id")
        reports.create_index("status")
        appeals = self.db["appeals"]
        appeals.create_index("report_id")
        appeals.create_index("user_id")
        users = self.db["users"]
        users.create_index("_id")
        admin_logs = self.db["admin_logs"]
        admin_logs.create_index("created_at")

    def get_collection(self, name):
        # Auto-reconnect on failure with retry
        for attempt in range(3):
            try:
                return self.db[name]
            except (AutoReconnect, ConnectionFailure) as e:
                logger.warning(f"MongoDB auto-reconnect attempt {attempt+1}: {e}")
                time.sleep(1)
                self.connect()
        raise Exception("MongoDB unavailable after retries")

db_manager = MongoManager(MONGO_URI, DB_NAME)

def get_collection(name):
    return db_manager.get_collection(name)

# ----------------------------- DB RETRY DECORATOR ----------------------------
def retry_on_failure(max_attempts=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (AutoReconnect, ConnectionFailure) as e:
                    last_error = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay * (2 ** attempt))
                    else:
                        logger.error(f"DB operation failed after {max_attempts} attempts: {e}")
                        raise
                except PyMongoError as e:
                    logger.error(f"MongoDB error in {func.__name__}: {e}")
                    raise
            raise last_error
        return wrapper
    return decorator

# ----------------------------- STATE MANAGEMENT (THREAD-SAFE) --------------
user_states: Dict[int, Dict] = {}
admin_pending: Dict[int, Dict] = {}
state_lock = threading.Lock()

def clear_user_state(user_id: int):
    with state_lock:
        user_states.pop(user_id, None)

def set_user_state(user_id: int, step: str, temp_data: dict = None, prev_step: str = None):
    with state_lock:
        user_states[user_id] = {
            'step': step,
            'temp_data': temp_data or {},
            'prev_step': prev_step,
            'timestamp': time.time()
        }

def get_user_state(user_id: int) -> Optional[Dict]:
    with state_lock:
        return user_states.get(user_id)

# ----------------------------- STALE STATE CLEANUP THREAD --------------------
CLEANUP_INTERVAL = 1800   # 30 minutes
STATE_TIMEOUT = 1800      # 30 minutes

def cleanup_stale_states():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        with state_lock:
            to_delete = []
            for uid, state in user_states.items():
                if now - state.get('timestamp', now) > STATE_TIMEOUT:
                    to_delete.append(uid)
            for uid in to_delete:
                del user_states[uid]
            # Clean admin_pending as well
            for aid in list(admin_pending.keys()):
                if now - admin_pending[aid].get('timestamp', now) > STATE_TIMEOUT:
                    del admin_pending[aid]
        if to_delete:
            logger.info(f"Cleaned up {len(to_delete)} stale user states")

# Start cleanup thread (daemon so it exits when main thread ends)
cleanup_thread = threading.Thread(target=cleanup_stale_states, daemon=True)
cleanup_thread.start()

# ----------------------------- HELPER FUNCTIONS ----------------------------
def escape_html(text: str) -> str:
    return html_module.escape(text, quote=False)

@retry_on_failure()
def get_next_sequence(name: str) -> int:
    col = get_collection("counters")
    result = col.find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=pymongo.ReturnDocument.AFTER
    )
    return result["seq"]

@retry_on_failure()
def add_user(user_id: int, username: str, first_name: str):
    col = get_collection("users")
    col.update_one(
        {"_id": user_id},
        {"$set": {"username": username, "first_name": first_name, "created_at": datetime.now().isoformat()}},
        upsert=True
    )

def generate_report_id() -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def clean_identifier(identifier: str) -> str:
    identifier = identifier.strip()
    if identifier.startswith('@'):
        identifier = identifier[1:]
    return identifier

def resolve_profile_link(identifier: str) -> str:
    identifier = clean_identifier(identifier)
    if identifier.isdigit():
        return f"tg://openmessage?user_id={identifier}"
    else:
        return f"https://t.me/{identifier}"

def validate_username_or_id(identifier: str) -> bool:
    identifier = clean_identifier(identifier)
    if not identifier:
        return False
    if identifier.isdigit():
        return len(identifier) >= 5 and int(identifier) > 0
    pattern = r'^[a-zA-Z][a-zA-Z0-9_]{4,31}$'
    if re.match(pattern, identifier):
        blacklist = {'test', 'user', 'aaa', 'fake', 'scammer', 'example', 'username'}
        if identifier.lower() in blacklist:
            return False
        return True
    return False

def validate_url(url: str) -> bool:
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        return False
    telegram_patterns = [
        r'^https?://t\.me/[\w_]+$',
        r'^https?://t\.me/joinchat/[\w_-]+$',
        r'^https?://t\.me/\+[\w-]+$',
        r'^https?://telegram\.me/[\w_]+$',
        r'^https?://telegram\.dog/[\w_]+$',
    ]
    if any(re.match(p, url, re.IGNORECASE) for p in telegram_patterns):
        return True
    general_pattern = r'^https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
    if re.match(general_pattern, url):
        blocked = {'localhost', '127.0.0.1', '0.0.0.0'}
        hostname = url.split('/')[2]
        if hostname in blocked:
            return False
        return True
    return False

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def safe_send(chat_id: int, text: str, reply_markup=None, photo=None, parse_mode='HTML'):
    try:
        if photo:
            return bot.send_photo(chat_id, photo, caption=text, reply_markup=reply_markup, parse_mode=parse_mode)
        else:
            return bot.send_message(chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
    except Exception as e:
        logger.error(f"Failed to send to {chat_id}: {e}")
        return None

def unban_and_restore_user(chat_id: int, user_id: Union[int, str]) -> bool:
    if not chat_id or not user_id:
        return False
    try:
        user_id_int = int(user_id)
        bot.unban_chat_member(chat_id, user_id_int)
        bot.restrict_chat_member(
            chat_id, user_id_int,
            can_send_messages=True,
            can_send_media_messages=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True
        )
        logger.info(f"Unbanned/restored user {user_id_int} in chat {chat_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to unban/restore user {user_id} in chat {chat_id}: {e}")
        return False

def log_to_db(actor_id: int, action: str, details: str):
    """Generic logging for all actions, not just admins."""
    col = get_collection("admin_logs")
    col.insert_one({
        "actor_id": actor_id,
        "action": action,
        "details": details,
        "created_at": datetime.now().isoformat()
    })

# ----------------------------- KEYBOARD BUILDERS ----------------------------
def reply_main_menu():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(KeyboardButton("📝 Create report"), KeyboardButton("⚖️ Appeal"))
    return kb

def reply_report_type():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(KeyboardButton("📱 Telegram"), KeyboardButton("🎭 Impersonator"))
    kb.add(KeyboardButton("🔙 Back"), KeyboardButton("🏠 Main Menu"))
    return kb

def reply_nav():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=3)
    kb.add(KeyboardButton("🔙 Back"), KeyboardButton("❌ Cancel"), KeyboardButton("🏠 Main Menu"))
    return kb

def admin_report_buttons(report_id: int):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✅ Approve", callback_data=f"approve_report|{report_id}"),
        InlineKeyboardButton("❌ Reject", callback_data=f"reject_report|{report_id}")
    )
    return kb

def admin_appeal_buttons(appeal_id: int):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✅ Accept Appeal", callback_data=f"accept_appeal|{appeal_id}"),
        InlineKeyboardButton("❌ Reject Appeal", callback_data=f"reject_appeal|{appeal_id}")
    )
    return kb

# ----------------------------- DATABASE OPERATIONS (with retry) ------------
@retry_on_failure()
def add_report(reporter_id: int, scammer_username: str, deal_amount: str,
               summary: str, proof_url: str, scam_type: str,
               scammer_is_username: bool = None,
               scammer_link: str = None,
               scammer_user_id: int = None,
               fake_profile: str = None, real_owner: str = None,
               fake_is_username: bool = None, fake_link: str = None,
               fake_user_id: int = None,
               real_is_username: bool = None, real_link: str = None,
               real_user_id: int = None) -> Tuple[int, str]:
    unique_id = generate_report_id()
    report_id = get_next_sequence("report_id")
    doc = {
        "_id": report_id,
        "report_unique_id": unique_id,
        "reporter_id": reporter_id,
        "scammer_username": scammer_username,
        "scammer_is_username": scammer_is_username,
        "scammer_link": scammer_link,
        "scammer_user_id": scammer_user_id,
        "deal_amount": deal_amount,
        "summary": summary,
        "proof_url": proof_url,
        "scam_type": scam_type,
        "status": "pending",
        "rejection_reason": None,
        "created_at": datetime.now().isoformat(),
        "approved_at": None,
        "channel_message_id": None,
        "real_owner": real_owner,
        "fake_profile": fake_profile,
        "fake_is_username": fake_is_username,
        "fake_link": fake_link,
        "fake_user_id": fake_user_id,
        "real_is_username": real_is_username,
        "real_link": real_link,
        "real_user_id": real_user_id,
    }
    col = get_collection("reports")
    col.insert_one(doc)
    return report_id, unique_id

@retry_on_failure()
def update_report_status(report_id: int, status: str, rejection_reason: str = None, channel_msg_id: int = None):
    fields = {"status": status}
    if status == 'approved':
        fields["approved_at"] = datetime.now().isoformat()
    if rejection_reason:
        fields["rejection_reason"] = rejection_reason
    if channel_msg_id:
        fields["channel_message_id"] = channel_msg_id
    col = get_collection("reports")
    col.update_one({"_id": report_id}, {"$set": fields})

@retry_on_failure()
def get_report_by_id(report_id: int) -> Optional[Dict]:
    col = get_collection("reports")
    return col.find_one({"_id": report_id})

@retry_on_failure()
def get_report_by_unique(unique_id: str) -> Optional[Dict]:
    col = get_collection("reports")
    return col.find_one({"report_unique_id": unique_id})

@retry_on_failure()
def get_pending_report_count(reporter_id: int, scammer_username: str) -> int:
    col = get_collection("reports")
    return col.count_documents({
        "reporter_id": reporter_id,
        "scammer_username": scammer_username,
        "status": {"$in": ["pending", "approved"]}
    })

@retry_on_failure()
def add_appeal(report_id: int, user_id: int, reason: str) -> int:
    appeal_id = get_next_sequence("appeal_id")
    doc = {
        "_id": appeal_id,
        "report_id": report_id,
        "user_id": user_id,
        "appeal_reason": reason,
        "status": "pending",
        "admin_response": None,
        "created_at": datetime.now().isoformat()
    }
    col = get_collection("appeals")
    col.insert_one(doc)
    return appeal_id

@retry_on_failure()
def get_appeal_by_id(appeal_id: int) -> Optional[Dict]:
    col = get_collection("appeals")
    return col.find_one({"_id": appeal_id})

@retry_on_failure()
def update_appeal_status(appeal_id: int, status: str, admin_response: str = None):
    fields = {"status": status}
    if admin_response:
        fields["admin_response"] = admin_response
    col = get_collection("appeals")
    col.update_one({"_id": appeal_id}, {"$set": fields})

# ----------------------------- PREMIUM UI TEMPLATES --------------------------
def scammer_display_html(identifier: str, is_username: bool, link: str) -> str:
    if is_username:
        return f"@{identifier}"
    else:
        return f'<a href="{link}">Click Here</a>'

def build_channel_caption(report: Dict) -> str:
    if report["scam_type"] == "impersonator":
        real = scammer_display_html(
            report["real_owner"],
            report["real_is_username"],
            report["real_link"]
        )
        return f"⚠️ Fake profile pretending to be {real}"
    else:
        scammer = scammer_display_html(
            report["scammer_username"],
            report["scammer_is_username"],
            report["scammer_link"]
        )
        return f"⚠️ User {scammer} has been marked as a scammer."

def build_admin_report(report: Dict) -> str:
    created = report.get('created_at', '')
    try:
        dt = datetime.fromisoformat(created)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        formatted_time = created

    if report["scam_type"] == "impersonator":
        fake = scammer_display_html(
            report["fake_profile"],
            report["fake_is_username"],
            report["fake_link"]
        )
        real = scammer_display_html(
            report["real_owner"],
            report["real_is_username"],
            report["real_link"]
        )
        reporter = f"@{report.get('reporter_username', 'Unknown')}" if report.get('reporter_username') else "Unknown"
        return (
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🚨 <b>NEW IMPERSONATOR REPORT</b> 🚨\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🆔 <b>Report ID:</b> <code>#{report['report_unique_id']}</code>\n"
            f"📂 <b>Type:</b> Impersonator\n\n"
            f"🎭 <b>Fake Profile:</b> {fake}\n"
            f"✅ <b>Real Owner:</b> {real}\n\n"
            f"👤 <b>Reporter:</b> {reporter}\n"
            f"⏰ <b>Submitted:</b> {formatted_time}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
    else:
        scammer = scammer_display_html(
            report["scammer_username"],
            report["scammer_is_username"],
            report["scammer_link"]
        )
        reporter = f"@{report.get('reporter_username', 'Unknown')}" if report.get('reporter_username') else "Unknown"
        amount = report.get("deal_amount", "0")
        summary = escape_html(report.get("summary", "No details"))
        proof = report.get("proof_url", "#")
        return (
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🚨 <b>NEW SCAM REPORT</b> 🚨\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🆔 <b>Report ID:</b> <code>#{report['report_unique_id']}</code>\n"
            f"📂 <b>Type:</b> Telegram Scam\n\n"
            f"👤 <b>Scammer:</b> {scammer}\n"
            f"💰 <b>Amount:</b> ₹{amount}\n"
            f"📝 <b>Summary:</b> {summary}\n"
            f"🔗 <b>Proof:</b> <a href='{proof}'>Click Here</a>\n\n"
            f"👤 <b>Reporter:</b> {reporter}\n"
            f"⏰ <b>Submitted:</b> {formatted_time}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )

def build_admin_appeal_message(appeal: Dict, report: Dict, user_username: str) -> str:
    scammer_disp = scammer_display_html(
        report.get("scammer_username") or report.get("fake_profile", ""),
        report.get("scammer_is_username") or report.get("fake_is_username", False),
        report.get("scammer_link") or report.get("fake_link", "#")
    )
    created = appeal.get('created_at', '')
    try:
        dt = datetime.fromisoformat(created)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        formatted_time = created
    return (
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⚖️ <b>NEW APPEAL REQUEST</b> ⚖️\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 <b>User:</b> @{user_username} (<code>{appeal['user_id']}</code>)\n"
        f"🆔 <b>Report ID:</b> <code>{report['report_unique_id']}</code>\n"
        f"🎭 <b>Scammer/Fake:</b> {scammer_disp}\n"
        f"📝 <b>Appeal Reason:</b>\n<blockquote>{escape_html(appeal['appeal_reason'])}</blockquote>\n"
        f"⏰ <b>Submitted:</b> {formatted_time}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

def edit_admin_message_with_status(msg, status_text, reviewer_username=None):
    try:
        old_text = msg.caption if msg.caption else msg.text
        if not old_text:
            return
        clean_text = re.sub(
            r"━━━━━━━━━━━━━━━━━━\n(✅|❌).*",
            "",
            old_text,
            flags=re.DOTALL
        ).strip()
        final_text = (
            f"{clean_text}\n\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{status_text}\n"
        )
        if reviewer_username:
            final_text += f"👮 <b>Reviewed By:</b> @{reviewer_username}\n"
        final_text += "━━━━━━━━━━━━━━━━━━"
        if msg.caption is not None:
            bot.edit_message_caption(
                chat_id=msg.chat.id,
                message_id=msg.message_id,
                caption=final_text,
                parse_mode="HTML",
                reply_markup=None
            )
        else:
            bot.edit_message_text(
                chat_id=msg.chat.id,
                message_id=msg.message_id,
                text=final_text,
                parse_mode="HTML",
                reply_markup=None
            )
    except Exception as e:
        logger.error(f"Admin message edit failed: {e}")

# ----------------------------- BOT STARTUP CHECK ---------------------------
def check_bot_rights():
    try:
        admins = bot.get_chat_administrators(SCAM_CHANNEL)
        bot_id = bot.get_me().id
        if not any(admin.user.id == bot_id for admin in admins):
            logger.warning(f"Bot is not admin in channel {SCAM_CHANNEL}. Cannot post.")
        else:
            logger.info(f"Bot is admin in {SCAM_CHANNEL}")
    except Exception as e:
        logger.error(f"Cannot verify channel admin rights: {e}")
    if GROUP_CHAT_ID:
        try:
            admins = bot.get_chat_administrators(GROUP_CHAT_ID)
            bot_id = bot.get_me().id
            if not any(admin.user.id == bot_id for admin in admins):
                logger.warning(f"Bot is not admin in group {GROUP_CHAT_ID}. Auto-unban will fail.")
            else:
                logger.info(f"Bot is admin in group {GROUP_CHAT_ID}")
        except Exception as e:
            logger.error(f"Cannot verify group admin rights: {e}")

# ----------------------------- BOT HANDLERS ----------------------------------
@bot.message_handler(commands=['start'])
def send_welcome(message: Message):
    user_id = message.from_user.id
    first_name = message.from_user.first_name
    username = message.from_user.username
    add_user(user_id, username, first_name)
    clear_user_state(user_id)

    welcome_text_html = (
        f"👋 𝗪𝗲𝗹𝗰𝗼𝗺𝗲 {first_name}! 𝘁𝗼 @ScamSafeXBot\n\n"
        "╭──────────────────────────────╮\n"
        "🛡️ 𝗔 𝘀𝗽𝗲𝗰𝗶𝗮𝗹𝗶𝘇𝗲𝗱 𝗽𝗹𝗮𝘁𝗳𝗼𝗿𝗺 𝗰𝗼𝗺𝗺𝗶𝘁𝘁𝗲𝗱 𝘁𝗼 𝗿𝗲𝗽𝗼𝗿𝘁𝗶𝗻𝗴 𝘀𝗰𝗮𝗺𝗺𝗲𝗿𝘀\n"
        "╰──────────────────────────────╯\n\n"
        "📌 • <a href='https://t.me/ScamSafeX/4'>𝗛𝗼𝘄 𝘁𝗼 𝗥𝗲𝗽𝗼𝗿𝘁 𝗮 𝗦𝗰𝗮𝗺𝗺𝗲𝗿</a>\n"
        "📌 • <a href='https://t.me/ScamSafeX/10'>𝗙𝗔𝗤 𝗮𝗻𝗱 𝗧𝗲𝗿𝗺𝘀</a>\n\n"
        "🔍 𝗔𝗹𝗹 𝗿𝗲𝗽𝗼𝗿𝘁𝘀 𝗮𝗿𝗲 𝗿𝗲𝘃𝗶𝗲𝘄𝗲𝗱 𝗯𝘆 𝗺𝗼𝗱𝘀 𝗯𝗲𝗳𝗼𝗿𝗲 𝗯𝗲𝗶𝗻𝗴 𝗽𝘂𝗯𝗹𝗶𝘀𝗵𝗲𝗱\n"
        "💬 𝗧𝘆𝗽𝗲 /help 𝗳𝗼𝗿 𝗮𝗹𝗹 𝗰𝗼𝗺𝗺𝗮𝗻𝗱𝘀 & 𝗳𝗲𝗮𝘁𝘂𝗿𝗲𝘀\n\n"
        "▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰\n"
        "✨ 𝗦𝗧𝗔𝗬 𝗦𝗔𝗙𝗘 • 𝗦𝗧𝗔𝗬 𝗦𝗘𝗖𝗨𝗥𝗘\n"
        "▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰\n\n"
    )
    powered_html = "⚡️ 𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬: <a href='https://t.me/ZyroX9'>@ZyroX9</a>"
    full_caption = welcome_text_html + powered_html
    bot.send_photo(user_id, WELCOME_IMAGE, caption=full_caption, parse_mode='HTML')
    bot.send_message(user_id, "📋 <b>Choose an option below:</b>", reply_markup=reply_main_menu(), parse_mode='HTML')

@bot.message_handler(commands=['help'])
def help_command(message: Message):
    help_text = (
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "📚 <b>𝗔𝘃𝗮𝗶𝗹𝗮𝗯𝗹𝗲 𝗖𝗼𝗺𝗺𝗮𝗻𝗱𝘀</b> 📚\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "/start - 𝗥𝗲𝘀𝘁𝗮𝗿𝘁 𝘁𝗵𝗲 𝗯𝗼𝘁 𝗮𝗻𝗱 𝘀𝗵𝗼𝘄 𝗺𝗮𝗶𝗻 𝗺𝗲𝗻𝘂\n"
        "/help - 𝗦𝗵𝗼𝘄 𝘁𝗵𝗶𝘀 𝗵𝗲𝗹𝗽 𝗺𝗲𝘀𝘀𝗮𝗴𝗲\n"
        "/cancel - 𝗖𝗮𝗻𝗰𝗲𝗹 𝗰𝘂𝗿𝗿𝗲𝗻𝘁 𝗼𝗽𝗲𝗿𝗮𝘁𝗶𝗼𝗻\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "📝 <b>𝗛𝗼𝘄 𝘁𝗼 𝗿𝗲𝗽𝗼𝗿𝘁 𝗮 𝘀𝗰𝗮𝗺𝗺𝗲𝗿</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "1️⃣ 𝗖𝗹𝗶𝗰𝗸 \"📝 𝗖𝗿𝗲𝗮𝘁𝗲 𝗿𝗲𝗽𝗼𝗿𝘁\"\n"
        "2️⃣ 𝗖𝗵𝗼𝗼𝘀𝗲 𝘀𝗰𝗮𝗺 𝘁𝘆𝗽𝗲 (𝗧𝗲𝗹𝗲𝗴𝗿𝗮𝗺 / 𝗜𝗺𝗽𝗲𝗿𝘀𝗼𝗻𝗮𝘁𝗼𝗿)\n"
        "3️⃣ 𝗣𝗿𝗼𝘃𝗶𝗱𝗲 𝘀𝗰𝗮𝗺𝗺𝗲𝗿 𝘂𝘀𝗲𝗿𝗻𝗮𝗺𝗲, 𝗮𝗺𝗼𝘂𝗻𝘁, 𝘀𝘂𝗺𝗺𝗮𝗿𝘆, 𝗽𝗿𝗼𝗼𝗳\n"
        "4️⃣ 𝗨𝗽𝗹𝗼𝗮𝗱 𝗽𝗿𝗼𝗼𝗳𝘀 𝗶𝗻 𝗮 𝗧𝗲𝗹𝗲𝗴𝗿𝗮𝗺 𝗰𝗵𝗮𝗻𝗻𝗲𝗹 𝗮𝗻𝗱 𝘀𝗲𝗻𝗱 𝘁𝗵𝗲 𝗹𝗶𝗻𝗸\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⚖️ <b>𝗔𝗽𝗽𝗲𝗮𝗹 𝗮 𝗿𝗲𝗷𝗲𝗰𝘁𝗲𝗱 𝗿𝗲𝗽𝗼𝗿𝘁</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "𝗖𝗹𝗶𝗰𝗸 \"⚖️ 𝗔𝗽𝗽𝗲𝗮𝗹\" 𝗮𝗻𝗱 𝗳𝗼𝗹𝗹𝗼𝘄 𝗶𝗻𝘀𝘁𝗿𝘂𝗰𝘁𝗶𝗼𝗻𝘀.\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📞 <b>𝗔𝗱𝗺𝗶𝗻 𝗖𝗼𝗻𝘁𝗮𝗰𝘁:</b> {OWNER_USERNAME}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    safe_send(message.chat.id, help_text, reply_markup=reply_main_menu())

@bot.message_handler(func=lambda msg: msg.text == "📝 Create report")
def create_report_button(msg: Message):
    clear_user_state(msg.chat.id)
    safe_send(msg.chat.id, "📋 <b>Select report type:</b>", reply_markup=reply_report_type())

@bot.message_handler(func=lambda msg: msg.text == "⚖️ Appeal")
def appeal_button(msg: Message):
    user_id = msg.chat.id
    clear_user_state(user_id)
    set_user_state(user_id, 'awaiting_appeal_identifier', {})
    safe_send(user_id, "⚖️ <b>Appeal Process</b>\n\nPlease enter your <b>username</b> or <b>Report ID</b> to appeal:",
              reply_markup=reply_nav())

@bot.message_handler(func=lambda msg: msg.text == "/cancel")
def cancel_command(msg: Message):
    clear_user_state(msg.chat.id)
    safe_send(msg.chat.id, "❌ Operation cancelled. Use /start to return to main menu.", reply_markup=reply_main_menu())

@bot.message_handler(func=lambda msg: msg.text in ["📱 Telegram", "🎭 Impersonator"])
def report_type_selected(msg: Message):
    user_id = msg.chat.id
    scam_type = "telegram" if msg.text == "📱 Telegram" else "impersonator"
    clear_user_state(user_id)
    if scam_type == "telegram":
        set_user_state(user_id, 'awaiting_scammer_username', {'scam_type': scam_type})
        safe_send(user_id, "👤 Enter the username or user ID of the user you would like to report:\n\nExample: @scammer or 123456789",
                  reply_markup=reply_nav())
    else:
        set_user_state(user_id, 'awaiting_fake_profile', {'scam_type': scam_type})
        safe_send(user_id, "🎭 Enter the <b>fake/impersonator</b> username or user ID:\n\nExample: @fakeuser or 123456789",
                  reply_markup=reply_nav())

@bot.message_handler(func=lambda msg: msg.text == "🔙 Back")
def back_button(msg: Message):
    user_id = msg.chat.id
    state = get_user_state(user_id)
    if not state:
        safe_send(user_id, "🏠 Main Menu", reply_markup=reply_main_menu())
        return
    step = state['step']
    temp = state.get('temp_data', {})
    if step in ('awaiting_scammer_username', 'awaiting_fake_profile'):
        clear_user_state(user_id)
        safe_send(user_id, "📋 <b>Select report type:</b>", reply_markup=reply_report_type())
    elif step == 'awaiting_amount':
        set_user_state(user_id, 'awaiting_scammer_username', temp)
        safe_send(user_id, "👤 Enter the username or user ID of the user you would like to report:", reply_markup=reply_nav())
    elif step in ('awaiting_summary', 'awaiting_summary_impersonator'):
        if temp.get('scam_type') == 'telegram':
            set_user_state(user_id, 'awaiting_amount', temp)
            safe_send(user_id, "💰 Enter the deal amount:\nExample: 5000", reply_markup=reply_nav())
        else:
            set_user_state(user_id, 'awaiting_fake_profile', temp)
            safe_send(user_id, "🎭 Enter the <b>fake/impersonator</b> username or user ID:", reply_markup=reply_nav())
    elif step in ('awaiting_proof_url', 'awaiting_proof_url_impersonator'):
        if temp.get('scam_type') == 'telegram':
            set_user_state(user_id, 'awaiting_summary', temp)
            safe_send(user_id, "📝 Write a short summary of what happened...", reply_markup=reply_nav())
        else:
            set_user_state(user_id, 'awaiting_real_owner', temp)
            safe_send(user_id, "👤 Now enter the <b>real/original owner</b> username or user ID:", reply_markup=reply_nav())
    elif step == 'awaiting_real_owner':
        set_user_state(user_id, 'awaiting_fake_profile', temp)
        safe_send(user_id, "🎭 Enter the <b>fake/impersonator</b> username or user ID:", reply_markup=reply_nav())
    elif step == 'awaiting_appeal_identifier':
        clear_user_state(user_id)
        safe_send(user_id, "🏠 Main Menu", reply_markup=reply_main_menu())
    elif step == 'awaiting_appeal_reason':
        set_user_state(user_id, 'awaiting_appeal_identifier', temp)
        safe_send(user_id, "⚖️ <b>Appeal Process</b>\n\nPlease enter your <b>username</b> or <b>Report ID</b> to appeal:", reply_markup=reply_nav())
    else:
        clear_user_state(user_id)
        safe_send(user_id, "🏠 Main Menu", reply_markup=reply_main_menu())

@bot.message_handler(func=lambda msg: msg.text == "❌ Cancel")
def cancel_flow(msg: Message):
    clear_user_state(msg.chat.id)
    safe_send(msg.chat.id, "❌ Operation cancelled. Returning to main menu.", reply_markup=reply_main_menu())

@bot.message_handler(func=lambda msg: msg.text == "🏠 Main Menu")
def main_menu_button(msg: Message):
    clear_user_state(msg.chat.id)
    safe_send(msg.chat.id, "🏠 <b>Main Menu</b>", reply_markup=reply_main_menu())

# ----------------------------- CALLBACK QUERY HANDLER -----------------------
@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call: CallbackQuery):
    user_id = call.from_user.id
    data = call.data

    if data.startswith("approve_report|"):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "⛔ Unauthorized.", show_alert=True)
            return
        report_id = int(data.split('|')[1])
        approve_report_action(report_id, call)
    elif data.startswith("reject_report|"):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "⛔ Unauthorized.", show_alert=True)
            return
        report_id = int(data.split('|')[1])
        admin_pending[user_id] = {
            'action': 'reject_report',
            'report_id': report_id,
            'msg': call.message,
            'timestamp': time.time()
        }
        bot.edit_message_text(f"❗ Please send the rejection reason for report #{report_id}:",
                              chat_id=user_id, message_id=call.message.message_id,
                              reply_markup=InlineKeyboardMarkup().add(
                                  InlineKeyboardButton("❌ Cancel", callback_data="cancel_admin_action")))
        bot.answer_callback_query(call.id)
    elif data.startswith("accept_appeal|"):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "⛔ Unauthorized.", show_alert=True)
            return
        appeal_id = int(data.split('|')[1])
        accept_appeal_action(appeal_id, call)
    elif data.startswith("reject_appeal|"):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "⛔ Unauthorized.", show_alert=True)
            return
        appeal_id = int(data.split('|')[1])
        admin_pending[user_id] = {
            'action': 'reject_appeal',
            'appeal_id': appeal_id,
            'msg': call.message,
            'timestamp': time.time()
        }
        bot.edit_message_text(f"❗ Please send the rejection reason for appeal #{appeal_id}:",
                              chat_id=user_id, message_id=call.message.message_id,
                              reply_markup=InlineKeyboardMarkup().add(
                                  InlineKeyboardButton("❌ Cancel", callback_data="cancel_admin_action")))
        bot.answer_callback_query(call.id)
    elif data == "cancel_admin_action":
        admin_pending.pop(user_id, None)
        bot.edit_message_text("Action cancelled.", chat_id=user_id, message_id=call.message.message_id, reply_markup=None)
        bot.answer_callback_query(call.id)

def approve_report_action(report_id: int, call: CallbackQuery):
    report = get_report_by_id(report_id)
    if not report:
        bot.edit_message_text("❌ Report not found.", chat_id=call.message.chat.id, message_id=call.message.message_id)
        return
    if report['status'] != 'pending':
        bot.answer_callback_query(call.id, "Report already processed.", show_alert=True)
        return

    admin_id = call.from_user.id
    admin_username = call.from_user.username or "Admin"

    # Post to channel FIRST, then update DB
    try:
        caption = build_channel_caption(report)
        channel_kb = InlineKeyboardMarkup(row_width=2)
        if report['scam_type'] == 'impersonator':
            channel_kb.add(
                InlineKeyboardButton("🚫 Fake Profile", url=report["fake_link"]),
                InlineKeyboardButton("✅ Real Profile", url=report["real_link"])
            )
        else:
            channel_kb.add(
                InlineKeyboardButton("👤 Profile", url=report["scammer_link"]),
                InlineKeyboardButton("📎 Proof", url=report["proof_url"])
            )
        sent = bot.send_photo(SCAM_CHANNEL, SCAM_ALERT_IMAGE, caption=caption,
                              reply_markup=channel_kb, parse_mode='HTML')
        # Success: update DB
        update_report_status(report_id, 'approved', channel_msg_id=sent.message_id)
        reporter_id = report['reporter_id']
        unique_id = report['report_unique_id']
        safe_send(reporter_id, f"✅ Your report ({unique_id}) has been approved.", reply_markup=reply_main_menu())
        log_to_db(admin_id, "approve_report", f"Report {report_id}")
        status_text = f"✅ <b>STATUS: ACCEPTED</b>"
        edit_admin_message_with_status(call.message, status_text, admin_username)
        bot.answer_callback_query(call.id)
    except Exception as e:
        logger.error(f"Channel post error: {e}")
        safe_send(admin_id, f"⚠️ Failed to post in channel: {e}. Report remains pending.")
        bot.answer_callback_query(call.id, "Failed to post to channel. Report not approved.", show_alert=True)

def accept_appeal_action(appeal_id: int, call: CallbackQuery):
    appeal = get_appeal_by_id(appeal_id)
    if not appeal:
        bot.edit_message_text("Appeal not found.", chat_id=call.message.chat.id, message_id=call.message.message_id)
        return
    report = get_report_by_id(appeal['report_id'])
    if not report:
        bot.edit_message_text("Associated report not found.", chat_id=call.message.chat.id, message_id=call.message.message_id)
        return

    target_user_id = None
    if report['scam_type'] == 'telegram':
        target_user_id = report.get('scammer_user_id')
    else:
        target_user_id = report.get('fake_user_id')

    if GROUP_CHAT_ID and target_user_id:
        unban_and_restore_user(GROUP_CHAT_ID, target_user_id)
    elif GROUP_CHAT_ID and not target_user_id:
        logger.warning(f"Appeal accepted but no numeric user ID for report {report['_id']} - cannot auto-unban.")

    # Remove from channel if previously approved
    if report.get('channel_message_id') and report['status'] == 'approved':
        try:
            bot.delete_message(SCAM_CHANNEL, report['channel_message_id'])
        except Exception as e:
            logger.error(f"Delete channel message failed: {e}")

    reports_col = get_collection("reports")
    reports_col.update_one({"_id": appeal['report_id']}, {"$set": {"status": "appealed_removed"}})
    update_appeal_status(appeal_id, 'accepted')
    safe_send(appeal['user_id'],
              f"✅ Your appeal for report {report['report_unique_id']} has been accepted. The report has been removed from the channel.",
              reply_markup=reply_main_menu())

    admin_username = call.from_user.username or "Admin"
    status_text = f"✅ <b>STATUS: APPEAL ACCEPTED</b>"
    edit_admin_message_with_status(call.message, status_text, admin_username)
    log_to_db(call.from_user.id, "accept_appeal", f"Appeal {appeal_id}")
    bot.answer_callback_query(call.id)

def reject_appeal_action(appeal_id: int, call: Optional[CallbackQuery], reason: str):
    appeal = get_appeal_by_id(appeal_id)
    if not appeal:
        return
    update_appeal_status(appeal_id, 'rejected', reason)
    safe_send(appeal['user_id'], f"❌ Your appeal was rejected.\n\n<b>Reason:</b> {reason}", reply_markup=reply_main_menu())
    if call:
        admin_username = call.from_user.username or "Admin"
        status_text = f"❌ <b>STATUS: APPEAL REJECTED</b>\n📝 <b>Reason:</b> {escape_html(reason)}"
        edit_admin_message_with_status(call.message, status_text, admin_username)
        bot.answer_callback_query(call.id)
    log_to_db(call.from_user.id if call else ADMIN_IDS[0], "reject_appeal", f"Appeal {appeal_id}")

# ----------------------------- TEXT HANDLERS FOR FLOW -----------------------
@bot.message_handler(func=lambda msg: get_user_state(msg.from_user.id) is not None)
def handle_state_messages(message: Message):
    user_id = message.from_user.id
    state = get_user_state(user_id)
    if not state:
        return

    step = state['step']
    temp = state['temp_data']
    scam_type = temp.get('scam_type', 'telegram')

    # Telegram flow
    if step == 'awaiting_scammer_username' and scam_type == 'telegram':
        raw_input = message.text.strip()
        if raw_input in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        scammer_input = clean_identifier(raw_input)
        if not validate_username_or_id(scammer_input):
            bot.reply_to(message, "❌ Invalid username or ID. Use a valid Telegram username (5-32 chars, a-z, 0-9, _) or numeric ID.", reply_markup=reply_nav())
            return
        is_username = not scammer_input.isdigit()
        link = resolve_profile_link(scammer_input)
        user_id_int = int(scammer_input) if scammer_input.isdigit() else None
        temp.update({
            'scammer_username': scammer_input,
            'scammer_is_username': is_username,
            'scammer_link': link,
            'scammer_user_id': user_id_int
        })
        set_user_state(user_id, 'awaiting_amount', temp)
        bot.reply_to(message, "💰 Enter the deal amount (how much scam happened):\nExample: 5000", reply_markup=reply_nav())

    elif step == 'awaiting_amount' and scam_type == 'telegram':
        amount = message.text.strip()
        if amount in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        if not amount.isdigit() or int(amount) <= 0:
            bot.reply_to(message, "❌ Please enter a valid positive number:", reply_markup=reply_nav())
            return
        temp['deal_amount'] = amount
        set_user_state(user_id, 'awaiting_summary', temp)
        bot.reply_to(message, "📝 Write a short summary of what happened.\n\nPlease explain clearly in Hindi or English.", reply_markup=reply_nav())

    elif step == 'awaiting_summary' and scam_type == 'telegram':
        summary = message.text.strip()
        if summary in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        if len(summary) < 10:
            bot.reply_to(message, "❌ Summary too short. Provide more details (min 10 characters).", reply_markup=reply_nav())
            return
        temp['summary'] = summary
        set_user_state(user_id, 'awaiting_proof_url', temp)
        bot.reply_to(message, "🔗 Please create a Telegram channel and upload all proofs/screenshots there.\nOnce done, send the channel URL.\nExample: https://t.me/your_proof_channel", reply_markup=reply_nav())

    elif step == 'awaiting_proof_url' and scam_type == 'telegram':
        proof_url = message.text.strip()
        if proof_url in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        if not validate_url(proof_url):
            bot.reply_to(message, "❌ Invalid URL. Provide a valid Telegram channel link (t.me/...) or a valid HTTPS URL.", reply_markup=reply_nav())
            return
        temp['proof_url'] = proof_url
        scammer = temp['scammer_username']
        if get_pending_report_count(user_id, scammer) > 0:
            bot.reply_to(message, "⚠️ You already have a pending or approved report against this user.", reply_markup=reply_main_menu())
            clear_user_state(user_id)
            return
        report_id, unique_id = add_report(
            user_id,
            scammer,
            temp.get('deal_amount', '0'),
            temp['summary'],
            proof_url,
            scam_type,
            scammer_is_username=temp['scammer_is_username'],
            scammer_link=temp['scammer_link'],
            scammer_user_id=temp.get('scammer_user_id')
        )
        scammer_disp = f"@{scammer}" if temp['scammer_is_username'] else "User"
        bot.reply_to(message, f"✅ Your report has been submitted successfully.\n\n<b>Report ID:</b> {unique_id}\nScammer: {scammer_disp}",
                     parse_mode='HTML', reply_markup=reply_main_menu())
        report_data = get_report_by_id(report_id)
        report_data['reporter_username'] = message.from_user.username
        admin_msg = build_admin_report(report_data)
        for admin_id in ADMIN_IDS:
            safe_send(admin_id, admin_msg, reply_markup=admin_report_buttons(report_id))
        log_to_db(user_id, "report_submitted", f"Report {unique_id} from {user_id}")
        clear_user_state(user_id)

    # Impersonator flow
    elif step == 'awaiting_fake_profile' and scam_type == 'impersonator':
        raw_input = message.text.strip()
        if raw_input in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        fake_input = clean_identifier(raw_input)
        if not validate_username_or_id(fake_input):
            bot.reply_to(message, "❌ Invalid username or ID.", reply_markup=reply_nav())
            return
        is_username = not fake_input.isdigit()
        link = resolve_profile_link(fake_input)
        user_id_int = int(fake_input) if fake_input.isdigit() else None
        temp.update({
            'fake_profile': fake_input,
            'fake_is_username': is_username,
            'fake_link': link,
            'fake_user_id': user_id_int
        })
        set_user_state(user_id, 'awaiting_real_owner', temp)
        bot.reply_to(message, "👤 Now enter the <b>real/original owner</b> username or user ID:\n\nExample: @realuser or 123456789", reply_markup=reply_nav(), parse_mode='HTML')

    elif step == 'awaiting_real_owner' and scam_type == 'impersonator':
        raw_input = message.text.strip()
        if raw_input in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        real_input = clean_identifier(raw_input)
        if not validate_username_or_id(real_input):
            bot.reply_to(message, "❌ Invalid username or ID.", reply_markup=reply_nav())
            return
        is_username = not real_input.isdigit()
        link = resolve_profile_link(real_input)
        real_user_id_int = int(real_input) if real_input.isdigit() else None
        temp.update({
            'real_owner': real_input,
            'real_is_username': is_username,
            'real_link': link,
            'real_user_id': real_user_id_int
        })
        col = get_collection("reports")
        count = col.count_documents({
            "reporter_id": user_id,
            "fake_profile": temp['fake_profile'],
            "scam_type": "impersonator",
            "status": {"$in": ["pending", "approved"]}
        })
        if count > 0:
            bot.reply_to(message, "⚠️ You already have a pending or approved impersonator report against this fake profile.", reply_markup=reply_main_menu())
            clear_user_state(user_id)
            return
        report_id, unique_id = add_report(
            user_id, "", "0", "", "", 'impersonator',
            fake_profile=temp['fake_profile'],
            fake_is_username=temp['fake_is_username'],
            fake_link=temp['fake_link'],
            fake_user_id=temp.get('fake_user_id'),
            real_owner=temp['real_owner'],
            real_is_username=temp['real_is_username'],
            real_link=temp['real_link'],
            real_user_id=temp.get('real_user_id')
        )
        fake_disp = f"@{temp['fake_profile']}" if temp['fake_is_username'] else "User"
        real_disp = f"@{temp['real_owner']}" if temp['real_is_username'] else "User"
        bot.reply_to(message,
                     f"✅ Your impersonator report has been submitted.\n\n<b>Report ID:</b> {unique_id}\nFake: {fake_disp}\nReal: {real_disp}",
                     parse_mode='HTML', reply_markup=reply_main_menu())
        report_data = get_report_by_id(report_id)
        report_data['reporter_username'] = message.from_user.username
        admin_msg = build_admin_report(report_data)
        for admin_id in ADMIN_IDS:
            safe_send(admin_id, admin_msg, reply_markup=admin_report_buttons(report_id))
        log_to_db(user_id, "report_submitted", f"Impersonator Report {unique_id}")
        clear_user_state(user_id)

    # Appeal flow
    elif step == 'awaiting_appeal_identifier':
        identifier = clean_identifier(message.text.strip())
        if identifier in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        report = None
        if len(identifier) == 8 and identifier.isalnum():
            report = get_report_by_unique(identifier)
        else:
            col = get_collection("reports")
            report = col.find_one({
                "$or": [
                    {"scammer_username": identifier},
                    {"fake_profile": identifier},
                    {"real_owner": identifier}
                ],
                "status": {"$in": ["approved", "appealed_removed"]}
            })
        if not report:
            bot.reply_to(message, "❌ No report found. Try again.", reply_markup=reply_nav())
            return
        temp['report_id'] = report['_id']
        set_user_state(user_id, 'awaiting_appeal_reason', temp)
        bot.reply_to(message, "📝 <b>Explain why your report should be removed.</b>\nProvide clear justification:",
                     parse_mode='HTML', reply_markup=reply_nav())

    elif step == 'awaiting_appeal_reason':
        reason = message.text.strip()
        if reason in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
            return
        if len(reason) < 15:
            bot.reply_to(message, "❌ Reason too short. Please provide details (min 15 characters).", reply_markup=reply_nav())
            return
        report_id = temp.get('report_id')
        if not report_id:
            bot.reply_to(message, "Error: missing report. Restart appeal.", reply_markup=reply_main_menu())
            clear_user_state(user_id)
            return
        appeal_id = add_appeal(report_id, user_id, reason)
        report = get_report_by_id(report_id)
        admin_appeal_msg = build_admin_appeal_message(
            {"appeal_reason": reason, "user_id": user_id, "created_at": datetime.now().isoformat()},
            report,
            message.from_user.username or "Unknown"
        )
        for admin_id in ADMIN_IDS:
            safe_send(admin_id, admin_appeal_msg, reply_markup=admin_appeal_buttons(appeal_id))
        bot.reply_to(message, "✅ Your appeal has been submitted to admin for review.", reply_markup=reply_main_menu())
        clear_user_state(user_id)
    else:
        bot.reply_to(message, "Please use the buttons to navigate.", reply_markup=reply_main_menu())
        clear_user_state(user_id)

# ----------------------------- ADMIN REJECT REASON HANDLER ------------------
@bot.message_handler(func=lambda msg: is_admin(msg.from_user.id) and msg.from_user.id in admin_pending)
def handle_admin_reject_reason(message: Message):
    admin_id = message.from_user.id
    pending = admin_pending.get(admin_id)
    if not pending:
        return

    # Ignore commands or button texts
    if message.text.startswith('/') or message.text in ["🔙 Back", "❌ Cancel", "🏠 Main Menu"]:
        return

    reason = message.text.strip()
    if not reason:
        bot.reply_to(message, "Reason cannot be empty.")
        return

    action = pending['action']
    admin_msg_obj = pending.get('msg')

    if action == 'reject_report':
        report_id = pending['report_id']
        report = get_report_by_id(report_id)
        if report:
            update_report_status(report_id, 'rejected', reason)
            safe_send(report['reporter_id'], f"❌ Your report ({report['report_unique_id']}) was rejected.\n\n<b>Reason:</b> {reason}", reply_markup=reply_main_menu())
            if admin_msg_obj:
                admin_username = message.from_user.username or "Admin"
                status_text = f"❌ <b>STATUS: REJECTED</b>\n📝 <b>Reason:</b> {escape_html(reason)}"
                edit_admin_message_with_status(admin_msg_obj, status_text, admin_username)
            else:
                safe_send(admin_id, f"✅ Rejection recorded for report #{report_id}.")
            log_to_db(admin_id, "reject_report", f"Report {report_id}, reason: {reason}")
    elif action == 'reject_appeal':
        appeal_id = pending['appeal_id']
        reject_appeal_action(appeal_id, None, reason)
        if admin_msg_obj:
            admin_username = message.from_user.username or "Admin"
            status_text = f"❌ <b>STATUS: APPEAL REJECTED</b>\n📝 <b>Reason:</b> {escape_html(reason)}"
            edit_admin_message_with_status(admin_msg_obj, status_text, admin_username)
        else:
            safe_send(admin_id, f"✅ Appeal #{appeal_id} rejected.")
    del admin_pending[admin_id]

# ----------------------------- MAIN EXECUTION -------------------------------
if __name__ == "__main__":
    # Set bot username
    try:
        me = bot.get_me()
        BOT_USERNAME = f"@{me.username}"
        logger.info(f"Bot username set to {BOT_USERNAME}")
    except Exception as e:
        logger.error(f"Could not fetch bot username: {e}")
        BOT_USERNAME = "@ScamSafeXBot"

    # Remove webhook
    bot.remove_webhook()
    time.sleep(1)

    # Check bot rights in channel & group
    check_bot_rights()

    logger.info(f"Bot {BOT_USERNAME} running with admins: {ADMIN_IDS}")
    if GROUP_CHAT_ID:
        logger.info(f"Auto-unban group configured: {GROUP_CHAT_ID}")
    else:
        logger.warning("GROUP_CHAT_ID is not set. Auto-unban on appeal acceptance is disabled.")

    # Start polling with auto-restart
    while True:
        try:
            bot.infinity_polling(skip_pending=True, timeout=20)
        except Exception as e:
            logger.error(f"Polling crashed: {e}. Restarting in 10s...")
            time.sleep(10)
