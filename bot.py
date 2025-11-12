from dotenv import load_dotenv
load_dotenv()

import requests
import os
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Token'lar artık .env dosyasından okunacak
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
IPINFO_API_TOKEN = os.environ.get("IPINFO_API_TOKEN")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Merhaba! Ben OSINT botuyum. /ip <adres> komutu ile sorgulama yapabilirsiniz.")

async def ip_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        ip_adresi = context.args[0]
        api_url = f"https://ipinfo.io/{ip_adresi}/json?token={IPINFO_API_TOKEN}"
        
        response = requests.get(api_url)
        
        if response.status_code == 200:
            data = response.json()
            
            mesaj = f"🔍 **IP Sorgu Sonucu: {data.get('ip')}**\n\n"
            mesaj += f"📍 Konum: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}\n"
            mesaj += f"🏢 Organizasyon: {data.get('org', 'N/A')}\n"
            mesaj += f"🗺️ Koordinatlar: {data.get('loc', 'N/A')}\n"
            
            if data.get('loc'):
                mesaj += f"🌍 [Google Maps](https://www.google.com/maps/search/?api=1&query={data.get('loc')})"
            
            await update.message.reply_text(mesaj, parse_mode='Markdown')
        else:
            await update.message.reply_text(f"API hatası: {response.status_code}")
            
    except IndexError:
        await update.message.reply_text("Kullanım: /ip <IP_ADRESI>")
    except Exception as e:
        await update.message.reply_text(f"Bir hata oluştu: {str(e)}")

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ip", ip_sorgula))

    print("Bot çalışıyor... (Durdurmak için CTRL+C)")
    application.run_polling()

if __name__ == "__main__":
    main()
