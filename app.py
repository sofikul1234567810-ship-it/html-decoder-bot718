
import os
import re
import ast
import json
import base64
import binascii
import asyncio
import logging
import threading
from pathlib import Path
from html.parser import HTMLParser
from flask import Flask, jsonify

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ---------------- CONFIG ----------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "5"))
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

web = Flask(__name__)


@web.get("/")
def home():
    return "HTML Decode Telegram Bot is running!"


@web.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


def run_web_server():
    port = int(os.getenv("PORT", "10000"))
    web.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False,
    )


# ---------------- FILE HELPERS ----------------

def beautify_code(code: str, extension: str) -> str:
    """Basic formatter for HTML, XML, JSON, and JavaScript."""
    extension = extension.lower()

    if extension == ".json":
        try:
            return json.dumps(json.loads(code), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass

    if extension in (".html", ".htm", ".xml"):
        code = re.sub(r">\s*<", ">\n<", code.strip())
        lines = code.splitlines()
        result = []
        indent = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if re.match(r"</", line):
                indent = max(0, indent - 1)

            result.append("    " * indent + line)

            is_closing = line.startswith("</")
            is_comment = line.startswith("<!--")
            is_doctype = line.lower().startswith("<!doctype")
            is_void = bool(re.match(
                r"<(area|base|br|col|embed|hr|img|input|link|meta|"
                r"param|source|track|wbr)\b",
                line,
                re.I,
            ))
            is_self_closing = line.endswith("/>")

            if (
                line.startswith("<")
                and not is_closing
                and not is_comment
                and not is_doctype
                and not is_void
                and not is_self_closing
                and not re.search(r"</[^>]+>\s*$", line)
            ):
                indent += 1

        return "\n".join(result)

    # Keep JS and other text unchanged rather than risk damaging the code.
    return code


def decode_text(code: str) -> str:
    """Try common text encodings without executing the submitted code."""
    original = code

    # Decode JavaScript Unicode escapes such as \u0041.
    try:
        code = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            code,
        )
        code = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1), 16)),
            code,
        )
    except (ValueError, OverflowError):
        code = original

    # Decode percent-encoded text.
    try:
        from urllib.parse import unquote
        decoded = unquote(code)
        if decoded != code:
            code = decoded
    except Exception:
        pass

    # Decode a plain Base64 string if it looks like one.
    candidate = code.strip()
    if (
        len(candidate) >= 8
        and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", candidate)
        and len(candidate) % 4 == 0
    ):
        try:
            raw = base64.b64decode(candidate, validate=True)
            text = raw.decode("utf-8")
            if text and text.isprintable():
                code = text
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    return code


def analyze_code(code: str, filename: str) -> str:
    lines = code.splitlines()
    extension = Path(filename).suffix.lower()

    tags = re.findall(r"<\s*([a-zA-Z][\w:-]*)\b", code)
    scripts = len(re.findall(r"<\s*script\b", code, re.I))
    encoded_strings = len(re.findall(
        r"(?:atob\s*\(|fromCharCode\s*\(|eval\s*\(|"
        r"unescape\s*\(|decodeURIComponent\s*\()",
        code,
        re.I,
    ))

    result = [
        "📋 FILE ANALYSIS",
        f"📄 File: {filename}",
        f"📦 Type: {extension or 'Unknown'}",
        f"📝 Characters: {len(code)}",
        f"📏 Lines: {len(lines)}",
        f"🏷️ HTML tags found: {len(tags)}",
        f"📜 Script tags: {scripts}",
        f"🔎 Encoding/dynamic-code patterns: {encoded_strings}",
        "",
        "Note: This is a basic static analysis, not a full security audit.",
        "Uploaded code is never executed by this bot.",
    ]

    return "\n".join(result)


def read_text_file(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


async def send_result_file(
    update: Update,
    filename: str,
    content: str,
    caption: str,
):
    output = content.encode("utf-8")
    if len(output) > MAX_FILE_SIZE:
        await update.effective_message.reply_text(
            f"Output is larger than the {MAX_FILE_MB} MB limit."
        )
        return

    from io import BytesIO
    buffer = BytesIO(output)
    buffer.name = filename

    await update.effective_message.reply_document(
        document=buffer,
        filename=filename,
        caption=caption,
    )


# ---------------- BOT COMMANDS ----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "👋 Welcome to HTML Decode Bot!\n\n"
        "Send an HTML, JS, or TXT file to analyze it.\n\n"
        "Commands:\n"
        "/start - Start bot\n"
        "/help - Show help\n"
        "/analyze - Analyze the next uploaded file\n"
        "/beautify - Format the next uploaded file\n"
        "/decode - Try basic text decoding\n\n"
        f"Maximum file size: {MAX_FILE_MB} MB"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)


async def set_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = update.effective_message.text.split()[0].lower().lstrip("/")
    context.user_data["mode"] = mode
    await update.effective_message.reply_text(
        f"✅ Mode set to {mode.upper()}.\nNow send your file."
    )


async def handle_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    message = update.effective_message
    document = message.document

    if not document:
        return

    allowed = {".html", ".htm", ".js", ".mjs", ".cjs", ".txt", ".json", ".xml"}
    filename = Path(document.file_name or "uploaded.txt").name
    extension = Path(filename).suffix.lower()

    if extension not in allowed:
        await message.reply_text(
            "Unsupported file type. Send HTML, JS, TXT, JSON, or XML."
        )
        return

    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await message.reply_text(
            f"File too large. Maximum allowed size is {MAX_FILE_MB} MB."
        )
        return

    status = await message.reply_text("⏳ Processing your file...")

    try:
        telegram_file = await context.bot.get_file(document.file_id)
        data = await telegram_file.download_as_bytearray()

        if len(data) > MAX_FILE_SIZE:
            await status.edit_text("File exceeds the configured size limit.")
            return

        code = read_text_file(bytes(data))
        mode = context.user_data.pop("mode", "analyze")

        if mode == "analyze":
            report = analyze_code(code, filename)
            await status.edit_text(report[:4000])
            return

        if mode == "beautify":
            output = beautify_code(code, extension)
            out_name = f"{Path(filename).stem}_beautified{extension}"
            caption = "✅ Basic formatting complete."
        elif mode == "decode":
            output = decode_text(code)
            out_name = f"{Path(filename).stem}_decoded{extension or '.txt'}"
            caption = "✅ Basic decoding attempt complete. Some obfuscation cannot be reversed."
        else:
            output = code
            caption = "✅ File received."

        await status.delete()
        await send_result_file(update, out_name, output, caption)

    except Exception:
        logger.exception("File processing failed")
        try:
            await status.edit_text(
                "❌ Could not process the file. Please try again."
            )
        except Exception:
            pass


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("mode"):
        await update.effective_message.reply_text(
            "Please upload a supported file to use the selected mode."
        )
    else:
        await update.effective_message.reply_text(
            "Send an HTML/JS/TXT file, or use /help to see commands."
        )


# ---------------- ASYNC STARTUP ----------------

async def main():
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is missing. Add your Telegram bot token "
            "in Render Environment Variables."
        )

    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("analyze", set_mode))
    application.add_handler(CommandHandler("beautify", set_mode))
    application.add_handler(CommandHandler("decode", set_mode))
    application.add_handler(
        MessageHandler(filters.Document.ALL, handle_document)
    )
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text)
    )

    # Render health-check web server runs separately.
    threading.Thread(target=run_web_server, daemon=True).start()

    # Use the active asyncio event loop instead of run_polling().
    await application.initialize()
    await application.start()

    if application.updater is None:
        raise RuntimeError("Telegram polling updater is unavailable.")

    await application.updater.start_polling(drop_pending_updates=True)
    logger.info("Telegram bot started successfully.")

    try:
        await asyncio.Event().wait()
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
