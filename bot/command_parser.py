from __future__ import annotations

import os
import re
import asyncio
import logging
from typing import Optional

from telegram import Update, LinkPreviewOptions
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, Defaults

from ai.gemini_client import GeminiClient

from vcenter.vcenter_task import VCenterClient
from vcenter.vcenter_task import get_vm_events_by_name

from bot.user_management import (
    load_user_config,
    get_user_commands,
    get_user_info_from_update,
    require_any_access,
    require_user_or_admin,
    require_admin,
)
from bot.text_formatter import (
    format_vm_basic,
    format_vm_detailed,
    format_vm_events,
    format_error_message,
    format_success_message,
    format_warning_message,
    format_help_message,
    format_search_results,
    format_start_message,
    format_host_basic,
    format_host_detailed,
)
from cache.redis_index import connect as redis_connect, ensure_vm_index
from cache.cache_manager import flush_all_cache
from cache.cache_layer import (
    get_vm_info_by_name_cached_async,
    get_vm_info_by_ip_cached_async,
    find_vms_by_keyword_cached_async,
    get_host_info_cached_async,
)


# Keepalive to avoid frequent logins
try:
    from vcenter.keepalive_patch import attach_keepalive
except Exception:
    attach_keepalive = None

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

# Set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Globals
ai_client: Optional[GeminiClient] = None
vcenter_client: Optional[VCenterClient] = None
redis_client = None

IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
)

# Bot configuration
MAX_MESSAGE_LENGTH = 4096
DEFAULT_VM_EVENT_DAYS = 7
MAX_VM_EVENT_DAYS = 30

# -------------------- Init --------------------
def init_ai_client() -> Optional[GeminiClient]:
    """Initialize Gemini AI client."""
    try:
        client = GeminiClient()
        # Test API key availability
        if not client.api_key:
            logger.warning("Gemini API key not configured")
            return None
        logger.info("Gemini AI client initialized")
        return client
    except Exception as e:
        logger.error(f"Failed to initialize AI client: {e}")
        return None


def init_vcenter_client() -> Optional[VCenterClient]:
    """Initialize vCenter client with connection."""
    host = os.getenv("VCENTER_HOST")
    user = os.getenv("VCENTER_USER")
    pwd = os.getenv("VCENTER_PASSWORD")
    if not all([host, user, pwd]):
        logger.error("Missing VCENTER_* environment variables")
        return None

    client = VCenterClient(host, user, pwd)
    client.connect()

    # attach keepalive if available
    if attach_keepalive:
        try:
            attach_keepalive(client.get_instance(), 600)
            logger.info("KeepAlive attached")
        except Exception as e:
            logger.warning("KeepAlive not attached: %s", e)

    logger.info("Connected to vCenter at %s", host)
    return client


def init_redis():
    """Initialize Redis connection."""
    global redis_client
    url = os.getenv("REDIS_URL")
    if url:
        redis_client = redis_connect(url=url)
    else:
        redis_client = redis_connect(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
        )
    logger.info("Redis connected")


# -------------------- Helpers --------------------


def assert_ready() -> bool:
    """Check if bot services are ready."""
    if not vcenter_client:
        logger.error("vCenter not initialized")
        return False
    if not redis_client:
        logger.error("Redis not initialized")
        return False
    return True


def assert_ai_ready() -> bool:
    """Check if AI services are ready."""
    if not ai_client:
        logger.error("AI client not initialized")
        return False
    return True


async def send_long_message(
    update: Update, message: str, parse_mode: str = ParseMode.HTML
):
    """
    Send potentially long messages, splitting if necessary.
    """
    max_length = MAX_MESSAGE_LENGTH - 100  # Leave some buffer

    if len(message) <= max_length:
        await update.message.reply_text(
            message, parse_mode=parse_mode, disable_web_page_preview=True
        )
        return

    # Split message into chunks
    lines = message.split("\n")
    current_chunk = ""

    for line in lines:
        if len(current_chunk + line + "\n") > max_length:
            if current_chunk:
                await update.message.reply_text(
                    current_chunk.strip(),
                    parse_mode=parse_mode,
                    disable_web_page_preview=True,
                )
                current_chunk = line + "\n"
            else:
                # Single line too long, truncate it
                truncated_line = line[: max_length - 50] + "... [truncated]"
                await update.message.reply_text(
                    truncated_line, parse_mode=parse_mode, disable_web_page_preview=True
                )
                current_chunk = ""
        else:
            current_chunk += line + "\n"

    # Send remaining chunk
    if current_chunk:
        await update.message.reply_text(
            current_chunk.strip(), parse_mode=parse_mode, disable_web_page_preview=True
        )


def format_ai_response(response: str) -> str:
    """Format AI response for Telegram with safe HTML support."""
    # Remove any unsupported XML/HTML tags first
    response = re.sub(r"<(?!/?(?:b|i|u|s|code|pre|a|em|strong)\b)[^>]*>", "", response)

    # Convert markdown-style formatting to safe HTML
    response = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", response)
    response = re.sub(r"\*(.*?)\*", r"<i>\1</i>", response)

    # Handle code blocks - convert to simple text to avoid parsing issues
    response = re.sub(r"```(.*?)```", r"\n\1\n", response, flags=re.DOTALL)
    response = re.sub(r"`([^`]+)`", r'"\1"', response)

    # Handle headers (convert ## to bold)
    response = re.sub(r"^##\s+(.+)$", r"<b>\1</b>", response, flags=re.MULTILINE)

    return response


# -------------------- Command Handlers --------------------


@require_any_access
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Start command - show welcome message."""
    user_info = get_user_info_from_update(update)
    user_id: int | None = user_info.get("user_id")
    username: str | None = user_info.get("username")
    user_role: str | None = user_info.get("role")

    start_text = format_start_message(
        user_name=username,
        user_id=user_id,
        user_role=user_role,
    )

    await update.message.reply_text(
        start_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


@require_any_access
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Help command - show available commands based on user role."""
    user_info = get_user_info_from_update(update)
    user_id = user_info.get("user_id")
    username = user_info.get("username")
    user_role = user_info.get("role")

    commands = get_user_commands(user_id, username)
    help_text = format_help_message(commands, user_role)

    await update.message.reply_text(
        help_text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


@require_user_or_admin
async def vm_by_name(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    VM lookup by name with proper cache integration.
    Supports both basic and detailed views.
    """
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not context.args:
        await update.message.reply_text("Usage: /vm_name <vm_name>\n")
        return

    # Parse arguments
    vm_name = context.args[0].strip()

    # Determine user role for detail level
    user_info = get_user_info_from_update(update)
    user_role = user_info.get("role", "user")
    is_admin = user_role == "admin"

    await update.message.chat.send_action("typing")

    try:
        # Use cache layer that stores full data
        vm_info = await get_vm_info_by_name_cached_async(
            redis_client, vcenter_client, vm_name
        )

        if not vm_info:
            await update.message.reply_text(
                format_error_message(f"VM '{vm_name}' not found")
            )
            return

        # Format response based on requested detail level
        if is_admin:
            response = format_vm_detailed(vm_info)
        else:
            response = format_vm_basic(vm_info)

        # Add cache indicator
        cache_source = (
            "Cache" if vm_info.get("updated_at") else "vCenter"
        )
        response += f"\n\n<i>{cache_source}</i>"

        await send_long_message(update, response)

        logger.info(
            f"VM info request: {vm_name} (detail: (admin: {is_admin}) by user {update.effective_user.id}"
        )

    except Exception as e:
        logger.error(f"Error in vm_by_name for '{vm_name}': {e}")
        await update.message.reply_text(
            format_error_message(f"Error retrieving VM info: {str(e)}")
        )


@require_user_or_admin
async def vm_by_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """VM lookup by IP address."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not context.args:
        await update.message.reply_text("Usage: /vm_ip <IPv4_address>")
        return

    ip = context.args[0].strip()

    # Basic IPv4 validation
    IPV4_RE = re.compile(
        r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
    )
    if not IPV4_RE.match(ip):
        await update.message.reply_text(
            format_error_message("Invalid IPv4 address format")
        )
        return

    # Determine user role for detail level
    user_info = get_user_info_from_update(update)
    user_role = user_info.get("role", "user")
    is_admin = user_role == "admin"

    await update.message.chat.send_action("typing")

    try:
        # Usecache layer
        vm_info = await get_vm_info_by_ip_cached_async(redis_client, vcenter_client, ip)

        if not vm_info:
            await update.message.reply_text(
                format_error_message("No VM found for this IP address")
            )
            return

        # Format response based on requested detail level
        if is_admin:
            response = format_vm_detailed(vm_info)
        else:
            response = format_vm_basic(vm_info)

        # Add IP-specific context
        vm_ips = vm_info.get("ipv4_addresses", [])
        if len(vm_ips) > 1:
            response += f"\n\n<b>All IPs:</b> <code>{', '.join(vm_ips)}</code>"

        cache_source = (
            "Cache" if vm_info.get("updated_at") else "vCenter"
        )
        response += f"\n<i>{cache_source}</i>"

        await send_long_message(update, response)

        logger.info(
            f"VM IP lookup: {ip} -> {vm_info.get('name', 'unknown')} by user {update.effective_user.id}"
        )

    except Exception as e:
        logger.error(f"Error in vm_by_ip for '{ip}': {e}")
        await update.message.reply_text(
            format_error_message(f"Error retrieving VM info: {str(e)}")
        )


@require_user_or_admin
async def find_keywords(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Keyword search with better result handling."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not context.args:
        await update.message.reply_text("Usage: /find <keyword>")
        return

    keyword = " ".join(context.args).strip()
    if len(keyword) < 3:
        await update.message.reply_text(
            format_error_message("Search keyword must be at least 3 characters")
        )
        return

    await update.message.chat.send_action("typing")

    try:
        # Use keyword search
        vm_names = await find_vms_by_keyword_cached_async(
            redis_client, vcenter_client, keyword, limit=50
        )

        if not vm_names:
            response = format_search_results([], keyword)
        else:
            response = format_search_results(vm_names, keyword)

            # Add helpful hint for large result sets
            if len(vm_names) >= 50:
                response += "\n\n<i>💡 Results limited to 50. Use more specific keywords for better results.</i>"

        await send_long_message(update, response)

        logger.info(
            f"Keyword search: '{keyword}' -> {len(vm_names)} results by user {update.effective_user.id}"
        )

    except Exception as e:
        logger.error(f"Error in find_keywords for '{keyword}': {e}")
        await update.message.reply_text(
            format_error_message(f"Error searching VMs: {str(e)}")
        )


@require_user_or_admin
async def vm_events(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Get VM events for specified VM."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /vm_events <vm_name> [limit]\n"
            "limit: number of latest events to show (default: 10, max: 50 for admins, 20 for users)"
        )
        return

    vm_name = context.args[0].strip()

    user_info = get_user_info_from_update(update)
    user_role = user_info.get("role", "user")
    is_admin = user_role == "admin"

    # Default limit based on role
    default_limit = 10
    max_limit = 50 if is_admin else 20
    limit = default_limit

    if len(context.args) > 1:
        try:
            limit = int(context.args[1])
            if limit < 1 or limit > max_limit:
                await update.message.reply_text(
                    format_warning_message(
                        f"Limit must be between 1 and {max_limit}, using default: {default_limit}"
                    )
                )
                limit = default_limit
        except ValueError:
            await update.message.reply_text(
                format_warning_message(
                    f"Invalid limit parameter, using default: {default_limit}"
                )
            )

    await update.message.chat.send_action("typing")

    try:
        # FIXED: Use the new function signature (no days parameter)
        events_data = get_vm_events_by_name(vcenter_client, vm_name, limit)
        response = format_vm_events(events_data)

        role_indicator = f"👤 {user_role.title()} (latest {limit} events)"
        response += f"\n\n<i>{role_indicator}</i>"

        await send_long_message(update, response, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error in vm_events: {e}")
        await update.message.reply_text(
            format_error_message(f"Error retrieving VM events: {e}")
        )


@require_user_or_admin
async def host_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Get ESXi host information
    """
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /host_name <hostname>\n"
            "Shows basic info for users, detailed info for admins"
        )
        return

    host_name = " ".join(context.args).strip()

    # Determine detail level based on user role
    user_info = get_user_info_from_update(update)
    user_role = user_info.get("role", "user")
    is_admin = user_role == "admin"

    await update.message.chat.send_action("typing")

    try:
        # Use cache layer with role-based detail level
        host_info = await get_host_info_cached_async(
            redis_client, vcenter_client, host_name, detailed=is_admin
        )

        if not host_info:
            await update.message.reply_text(
                format_error_message(f"ESXi host '{host_name}' not found")
            )
            return

        # Format response based on user role
        if is_admin:
            response = format_host_detailed(host_info)
        else:
            response = format_host_basic(host_info)

        # Add role and cache indicator
        cache_source = (
            "Cache" if host_info.get("updated_at") else "vCenter"
        )
        role_indicator = f"👤 {user_role.title()}"
        response += f"\n\n<i>{cache_source} • {role_indicator}</i>"

        await send_long_message(update, response)

        logger.info(
            f"Host info request: {host_name} (admin: {is_admin}) by user {update.effective_user.id}"
        )

    except Exception as e:
        logger.error(f"Error in host_info for '{host_name}': {e}")
        await update.message.reply_text(
            format_error_message(f"Error retrieving host info: {str(e)}")
        )


# -------------------- ADMIN COMMANDS --------------------


@require_admin
async def ai_linux_basic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """AI-powered basic Linux system analysis."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not assert_ai_ready():
        await update.message.reply_text(
            format_error_message("AI service not available")
        )
        return

    if not context.args:
        await update.message.reply_text("Usage: /ai_linux_basic <ip_address>")
        return

    ip_address = " ".join(context.args).strip()

    IPV4_RE = re.compile(
        r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
    )
    if not IPV4_RE.match(ip_address):
        await update.message.reply_text(
            format_error_message("Invalid IPv4 address format")
        )
        return
    
    await update.message.chat.send_action("typing")

    try:
        # Send initial message
        status_message = await update.message.reply_text(
            "🔄 Gathering system data and analyzing with AI...\n"
            "This may take 30 seconds...",
            parse_mode=ParseMode.HTML,
        )

        # Get AI analysis
        ai_response = ai_client.analyze_ssh_data(ip_address, temperature=0.1)

        if ai_response.startswith("❌"):
            await status_message.edit_text(ai_response, parse_mode=ParseMode.HTML)
            return

        # Format and send response
        formatted_response = format_ai_response(ai_response)

        await send_long_message(update, formatted_response, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error in ai_linux_basic: {e}")
        await update.message.reply_text(
            format_error_message(f"Error in AI analysis: {e}")
        )


@require_admin
async def ai_linux_sec(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """AI-powered Linux security analysis."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    if not assert_ai_ready():
        await update.message.reply_text(
            format_error_message("AI service not available")
        )
        return

    if not context.args:
        await update.message.reply_text("Usage: /ai_linux_sec <ip_address>")
        return

    ip_address = " ".join(context.args).strip()

    IPV4_RE = re.compile(
        r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
    )
    if not IPV4_RE.match(ip_address):
        await update.message.reply_text(
            format_error_message("Invalid IPv4 address format")
        )
        return

    await update.message.chat.send_action("typing")

    try:
        # Send initial message
        status_message = await update.message.reply_text(
            "🛡️ Gathering security data and analyzing with AI...\n"
            "This may take 30 seconds...",
            parse_mode=ParseMode.HTML,
        )

        # Get AI security analysis
        ai_response = ai_client.analyze_security_data(ip_address, temperature=0.1)

        if ai_response.startswith("❌"):
            await status_message.edit_text(ai_response, parse_mode=ParseMode.HTML)
            return

        # Format and send response
        formatted_response = format_ai_response(ai_response)

        await send_long_message(update, formatted_response, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error in ai_linux_sec: {e}")
        await update.message.reply_text(
            format_error_message(f"Error in AI security analysis: {e}")
        )


@require_admin
async def flush_cache_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin command to flush all cache."""
    if not assert_ready():
        await update.message.reply_text(format_error_message("Service not ready"))
        return

    await update.message.chat.send_action("typing")

    try:
        result = flush_all_cache(redis_client, vcenter_client.host)

        if result.get("success"):
            message = (
                f"Cache flush completed:\n"
                f"• Documents deleted: {result['vm_documents_deleted']}\n"
                f"• Time taken: {result['elapsed_seconds']}s"
            )
            await update.message.reply_text(format_success_message(message))
        else:
            await update.message.reply_text(
                format_error_message(result.get("message", "Cache flush failed"))
            )

    except Exception as e:
        logger.error(f"Error in flush_cache: {e}")
        await update.message.reply_text(
            format_error_message(f"Error flushing cache: {e}")
        )


# -------------------- Error Handlers --------------------


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log errors caused by Updates."""
    logger.error(f"Exception while handling an update: {context.error}")

    # Try to send error message to user if update contains a message
    if isinstance(update, Update) and update.message:
        try:
            await update.message.reply_text(
                format_error_message(
                    "An unexpected error occurred. Please try again later."
                )
            )
        except Exception:
            pass  # Can't send message, just log


# -------------------- Main Bot Function --------------------


def telegram_bot() -> None:
    """Main bot function."""
    global vcenter_client, ai_client

    ai = init_ai_client()
    globals()["ai_client"] = ai

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN environment variable")

    # Initialize backends
    vcenter = init_vcenter_client()
    if not vcenter:
        raise RuntimeError("vCenter initialization failed")

    globals()["vcenter_client"] = vcenter
    init_redis()

    # Load user configuration
    load_user_config()

    # Ensure VM index exists
    ensure_vm_index(redis_client, vcenter.host)

    parse_mode = Defaults(
        parse_mode=ParseMode.HTML,
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )

    # Create application
    app = Application.builder().token(token).defaults(parse_mode).build()

    # Add command handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))

    # VM operation handlers (user + admin)
    app.add_handler(CommandHandler("find", find_keywords))
    app.add_handler(CommandHandler("vm_name", vm_by_name))
    app.add_handler(CommandHandler("vm_ip", vm_by_ip))
    app.add_handler(CommandHandler("vm_events", vm_events))
    app.add_handler(CommandHandler("host_name", host_info))

    # Admin-only handlers
    app.add_handler(CommandHandler("flush", flush_cache_cmd))
    app.add_handler(CommandHandler("ai_linux_basic", ai_linux_basic))
    app.add_handler(CommandHandler("ai_linux_sec", ai_linux_sec))

    # Error handler
    app.add_error_handler(error_handler)
    logger.info("Telegram bot starting...")

    # Start bot
    app.run_polling(close_loop=False)

