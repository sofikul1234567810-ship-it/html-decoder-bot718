# HTML Decode Telegram Bot

## GitHub upload
ZIP extract করে `app.py`, `requirements.txt`, `render.yaml`—এই তিনটি ফাইল Repository-র root-এ upload করো। এখন আলাদা `decoder` folder দরকার নেই।

## Render deploy
1. Render-এ New + → Web Service → GitHub repository connect করো।
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python app.py`
4. Environment-এ `BOT_TOKEN` = BotFather token যোগ করো। `MAX_FILE_MB` চাইলে `5` রাখো।
5. Deploy করো। `/health` endpoint-এ `{"ok": true}` দেখা উচিত।

## Telegram
Bot-এ `/start` পাঠাও। `/analyze`, `/beautify`, `/decode` দিয়ে mode বেছে নিয়ে HTML/JS/TXT file পাঠাও।

## সীমাবদ্ধতা
এটি static analysis এবং সীমিত literal decoder; সব obfuscation reverse করতে পারে না। Uploaded code execute করে না। Beautify formatting কিছু unusual code-এ আচরণ বদলাতে পারে, তাই output review করো। BotFather token secret রাখো।
