import os
import re
import base64
import binascii
import logging
import threading
from pathlib import PurePath
from io import BytesIO

from flask import Flask, jsonify
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("html-decode-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_MB", "5")) * 1024 * 1024
PORT = int(os.getenv("PORT", "10000"))

web = Flask(__name__)


@web.get("/")
def home():
    return jsonify({
        "service": "HTML Decode Telegram Bot",
        "status": "running",
        "usage": "Open your Telegram bot and send /start"
    })


@web.get("/health")
def health():
    return jsonify({"ok": True}), 200


def safe_filename(name):
    name = PurePath(name.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "output.txt")[:120]


def analyze_code(source):
    checks = [
        ("Hex-style escapes (\\xNN)", r"\\x[0-9a-fA-F]{2}"),
        ("Unicode escapes (\\uNNNN)", r"\\u[0-9a-fA-F]{4}"),
        ("Hex numeric literals", r"\b0x[0-9a-fA-F]{2,}\b"),
        ("Obfuscated identifiers (_0x...)", r"\b_0x[a-fA-F0-9]+\b"),
        ("eval() calls", r"\beval\s*\("),
        ("new Function() calls", r"\bnew\s+Function\s*\("),
        ("Base64 decode calls (atob)", r"\batob\s*\("),
        ("String.fromCharCode calls", r"\bString\s*\.\s*fromCharCode\s*\("),
        ("Possible anti-debug patterns", r"debugger\s*;|console\s*\.\s*clear"),
        ("Dynamic script creation", r"createElement\s*\(\s*['\"]script"),
        ("Long encoded-looking strings", r"['\"][A-Za-z0-9+/=_-]{160,}['\"]"),
    ]
    found = []
    for label, pattern in checks:
        count = len(re.findall(pattern, source, flags=re.I))
        if count:
            found.append(f"• {label}: {count} occurrence(s)")
    report = [
        "🔍 HTML/JavaScript Static Analysis",
        "",
        f"Characters: {len(source):,}",
        f"Lines: {source.count(chr(10)) + 1:,}",
        f"Whitespace-separated parts: {len(source.split()):,}",
        "",
        "Findings:",
    ]
    report += found or [
        "• সাধারণ checks-এ পরিচিত pattern পাওয়া যায়নি। এতে কোড obfuscation-মুক্ত বা নিরাপদ প্রমাণ হয় না।"
    ]
    report += [
        "",
        "সীমাবদ্ধতা:",
        "• এটি static pattern matching; কোড execute করা হয়নি।",
        "• ভুল positive/negative ফল হতে পারে। সব obfuscation বা encrypted code recover করা সম্ভব নয়।",
    ]
    return "\n".join(report)


def beautify_code(source):
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    # HTML: split tags into readable lines. Script/style contents are preserved as text.
    if re.search(r"<\s*(html|head|body|div|script|style|!doctype)\b", source, re.I):
        tokens = re.split(r"(<!--.*?-->|<[^>]+>)", source, flags=re.S)
        lines = []
        depth = 0
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            low = token.lower()
            if low.startswith("</"):
                depth = max(0, depth - 1)
                lines.append("    " * depth + token)
            else:
                lines.append("    " * depth + token)
                if (re.match(r"<[a-z][^>]*[^/]>", low)
                    and not re.match(r"<(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)\b", low)
                    and not low.startswith(("<!--", "<!doctype", "<?"))):
                    depth += 1
        return "\n".join(lines) + "\n"

    # Lightweight JS formatter; no parsing/evaluation.
    token_re = re.compile(
        r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/|'
        r'[A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+(?:\.\d+)?|===|!==|=>|==|!=|<=|>=|\+\+|--|&&|\|\||\?\?|'
        r'\+=|-=|\*=|/=|[{}()\[\];,.?:]|[^\s])', re.S
    )
    tokens = token_re.findall(source)
    lines, indent, line, prev = [], 0, "", ""

    def flush():
        nonlocal line
        if line.strip():
            lines.append("    " * indent + line.strip())
        line = ""

    for tok in tokens:
        if tok.startswith("//") or tok.startswith("/*"):
            line = (line + " " if line.strip() else "") + tok
            flush()
        elif tok == "}":
            flush()
            indent = max(0, indent - 1)
            line = "}"
            flush()
        elif tok == "{":
            line = (line.rstrip() + " " if line.strip() else "") + "{"
            flush()
            indent += 1
        elif tok == ";":
            line = line.rstrip() + ";"
            flush()
        elif tok == ",":
            line = line.rstrip() + ", "
        elif tok in (")", "]", "."):
            line = line.rstrip() + tok
        elif tok in ("(", "["):
            if prev and (prev.isidentifier() or prev in (")", "]", "}")):
                line = line.rstrip() + " "
            line += tok
        elif tok == ":":
            line = line.rstrip() + ": "
        elif tok in ("=", "+", "-", "*", "/", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "=>", "&&", "||", "??", "+=", "-=", "*=", "/="):
            line = line.rstrip() + f" {tok} "
        else:
            if line and not line.endswith((" ", "(", "[", ".")):
                line += " "
            line += tok
        prev = tok
    flush()
    return "\n".join(lines) + "\n"


def basic_decode(source):
    notes = []
    output = source

    # Decode only explicit \xNN and \uNNNN escapes inside quoted literals.
    string_re = re.compile(r"""(['"])(?:\\.|(?!\1)[^\\])*?\1""")

    def decode_escapes(match):
        s = match.group(0)
        quote, body = s[0], s[1:-1]
        changed = False

        def repl_hex(m):
            nonlocal changed
            changed = True
            return chr(int(m.group(1), 16))

        def repl_unicode(m):
            nonlocal changed
            changed = True
            return chr(int(m.group(1), 16))

        try:
            decoded = re.sub(r"\\x([0-9a-fA-F]{2})", repl_hex, body)
            decoded = re.sub(r"\\u([0-9a-fA-F]{4})", repl_unicode, decoded)
            if changed:
                notes.append("Quoted string-এর কিছু \\\\xNN/\\\\uNNNN escape decode হয়েছে।")
            decoded = decoded.replace("\\", "\\\\").replace(quote, "\\" + quote)
            return quote + decoded + quote
        except Exception:
            return s

    output = string_re.sub(decode_escapes, output)

    atob_re = re.compile(r"""atob\s*\(\s*(['"])([A-Za-z0-9+/=_-]{4,87384})\1\s*\)""", re.I)

    def decode_b64(match):
        try:
            value = match.group(2)
            value += "=" * ((4 - len(value) % 4) % 4)
            decoded = base64.b64decode(value, validate=False)
            if len(decoded) <= 65536:
                decoded_text = decoded.decode("utf-8")
                notes.append("কিছু literal atob('base64') value decode হয়েছে।")
                return repr(decoded_text)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
        return match.group(0)

    output = atob_re.sub(decode_b64, output)

    char_re = re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*((?:\d{1,5}\s*,\s*){1,2047}\d{1,5})\s*\)")

    def decode_chars(match):
        try:
            nums = [int(x.strip()) for x in match.group(1).split(",")]
            if all(0 <= n <= 65535 for n in nums):
                notes.append("কিছু literal String.fromCharCode(...) sequence decode হয়েছে।")
                return repr("".join(chr(n) for n in nums))
        except Exception:
            pass
        return match.group(0)

    output = char_re.sub(decode_chars, output)
    if not notes:
        notes.append("পরিচিত literal pattern পাওয়া যায়নি যেটি নিরাপদে decode করা যায়।")
    notes += [
        "কোনো eval()/Function() চালানো হয়নি।",
        "এটি basic decoder; সব obfuscation বা encrypted payload decode করতে পারে না।",
    ]
    return output, notes


HELP_TEXT = (
    "🧰 HTML Decode Bot\n\n"
    "একটি .html, .htm, .js, .mjs, .cjs বা .txt ফাইল পাঠাও।\n\n"
    "/analyze — ফাইল বিশ্লেষণ\n"
    "/beautify — কোড format/clean\n"
    "/decode — basic literal decode\n"
    "/help — সাহায্য\n\n"
    "কমান্ড পাঠিয়ে তারপর ফাইল দাও, অথবা ফাইলের caption-এ /analyze, /beautify বা /decode লেখো।\n\n"
    "⚠️ Bot ফাইলের কোড execute করে না। সব obfuscation decode করা সম্ভব নয়।"
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["mode"] = "analyze"
    await update.effective_message.reply_text("স্বাগতম!\n\n" + HELP_TEXT)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(HELP_TEXT)


async def set_mode(update, context, mode, label):
    context.user_data["mode"] = mode
    await update.effective_message.reply_text(f"পরের ফাইলের মোড: {label}। এখন ফাইল পাঠাও।")


async def analyze_cmd(update, context):
    await set_mode(update, context, "analyze", "Analysis")


async def beautify_cmd(update, context):
    await set_mode(update, context, "beautify", "Beautify")


async def decode_cmd(update, context):
    await set_mode(update, context, "decode", "Basic Decode")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    doc = message.document
    if not doc:
        return

    filename = safe_filename(doc.file_name or "uploaded_code.txt")
    if not filename.lower().endswith((".html", ".htm", ".js", ".txt", ".mjs", ".cjs")):
        await message.reply_text("সমর্থিত ফাইল: .html, .htm, .js, .mjs, .cjs, .txt")
        return
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        await message.reply_text(f"ফাইলটি বড়। সর্বোচ্চ সাইজ {MAX_FILE_BYTES // (1024 * 1024)} MB।")
        return

    mode = context.user_data.get("mode", "analyze")
    caption = (message.caption or "").lower()
    for candidate in ("analyze", "beautify", "decode"):
        if f"/{candidate}" in caption:
            mode = candidate
            break

    status = await message.reply_text("ফাইল প্রসেস করছি…")
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        raw = await tg_file.download_as_bytearray()
        if len(raw) > MAX_FILE_BYTES:
            await status.edit_text("ফাইলটি নির্ধারিত সাইজের চেয়ে বড়।")
            return
        source = bytes(raw).decode("utf-8", errors="replace")

        if mode == "analyze":
            report = analyze_code(source)
            await status.delete()
            for i in range(0, len(report), 3800):
                await message.reply_text(report[i:i + 3800])
            return

        if mode == "beautify":
            output = beautify_code(source)
            report = "✅ Beautify/format সম্পন্ন। এটি formatting, সম্পূর্ণ deobfuscation নয়।"
            suffix = "_beautified"
        else:
            output, notes = basic_decode(source)
            report = "🔎 Basic decode সম্পন্ন।\n" + "\n".join("• " + n for n in notes[:8])
            suffix = "_decoded"

        await status.delete()
        await message.reply_text(report)
        ext = filename.rsplit(".", 1)[-1] if "." in filename else "txt"
        stem = filename.rsplit(".", 1)[0] if "." in filename else filename
        out_name = safe_filename(f"{stem}{suffix}.{ext}")
        bio = BytesIO(output.encode("utf-8"))
        bio.name = out_name
        await message.reply_document(
            document=bio,
            filename=out_name,
            caption="Output file তৈরি হয়েছে। ব্যবহারের আগে কোড review করো; এটি execute করা হয়নি।"
        )
    except Exception:
        logger.exception("File processing failed")
        try:
            await status.edit_text("ফাইল প্রসেস করা যায়নি। ছোট, text-based HTML/JS/TXT ফাইল দিয়ে চেষ্টা করো।")
        except Exception:
            await message.reply_text("ফাইল প্রসেস করা যায়নি।")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if msg and msg.text and not msg.text.startswith("/"):
        await msg.reply_text("HTML/JS/TXT ফাইল document হিসেবে পাঠাও। সাহায্যের জন্য /help পাঠাও।")


def run_web():
    web.run(host="0.0.0.0", port=PORT, use_reloader=False)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is missing.")
    bot = Application.builder().token(BOT_TOKEN).build()
    bot.add_handler(CommandHandler("start", start))
    bot.add_handler(CommandHandler("help", help_command))
    bot.add_handler(CommandHandler("analyze", analyze_cmd))
    bot.add_handler(CommandHandler("beautify", beautify_cmd))
    bot.add_handler(CommandHandler("decode", decode_cmd))
    bot.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    bot.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    threading.Thread(target=run_web, daemon=True).start()
    logger.info("Starting bot")
    bot.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
