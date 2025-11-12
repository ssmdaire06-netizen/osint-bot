from dotenv import load_dotenv
load_dotenv()

import requests
import os
import whois 
import datetime
import asyncio
import json 
import sys
from telegram import Update, BotCommand
from telegram.ext import Application, CommandHandler, ContextTypes


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


async def domain_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        domain_adi = context.args[0]
        await update.message.reply_text(f"🔍 {domain_adi} için bilgiler sorgulanıyor... Lütfen bekleyin.")

        # --- BÖLÜM 1: WHOIS SORGUSU ---
        whois_mesaj = "--- WHOIS BİLGİSİ ---\n"
        try:
            w = whois.whois(domain_adi)
            
            # Tarih verilerini formatlamak için yardımcı fonksiyon
            def format_date(date_data):
                if isinstance(date_data, list):
                    return date_data[0].strftime('%Y-%m-%d')
                if isinstance(date_data, datetime.datetime):
                    return date_data.strftime('%Y-%m-%d')
                return "N/A"

            whois_mesaj += f"Kayıt Edici: {w.registrar}\n"
            whois_mesaj += f"Oluşturulma: {format_date(w.creation_date)}\n"
            whois_mesaj += f"Bitiş Tarihi: {format_date(w.expiration_date)}\n"
            
            if w.name_servers:
                whois_mesaj += f"İsim Sunucuları: {', '.join(w.name_servers)}\n"
            else:
                whois_mesaj += "İsim Sunucuları: Bulunamadı\n"

        except Exception as e:
            whois_mesaj += f"Whois bilgisi alınamadı. (Domain gizli veya bulunamadı)\n"

        # --- BÖLÜM 2: DNS SORGUSU (Google API) ---
        dns_mesaj = "\n--- DNS KAYITLARI ---\n"
        try:
            # A Kaydı (IP Adresi)
            a_response = requests.get(f"https://dns.google/resolve?name={domain_adi}&type=A")
            a_data = a_response.json()
            if a_data.get('Answer'):
                a_record = a_data['Answer'][0]['data']
                dns_mesaj += f"A Kaydı (IP): {a_record}\n"
            else:
                dns_mesaj += "A Kaydı (IP): Bulunamadı.\n"
            
            # MX Kaydı (Mail Sunucusu)
            mx_response = requests.get(f"https://dns.google/resolve?name={domain_adi}&type=MX")
            mx_data = mx_response.json()
            if mx_data.get('Answer'):
                mx_records = [item['data'].split(' ')[1] for item in mx_data['Answer']]
                dns_mesaj += f"MX Kayıtları (Mail): {', '.join(mx_records)}\n"
            else:
                dns_mesaj += "MX Kayıtları (Mail): Bulunamadı.\n"
                
        except Exception:
            dns_mesaj += "DNS kayıtları sorgulanamadı.\n"

        # --- SONUÇLARI BİRLEŞTİR ---
        mesaj = f"📄 **Domain Sorgu Sonucu: {domain_adi}**\n\n"
        mesaj += whois_mesaj
        mesaj += dns_mesaj
        
        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        await update.message.reply_text("Kullanım: /domain <domain.com>")
    except Exception as e:
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")



#----------------------------------------------------
# YENİ EMAIL FONKSİYONU (holehe - Subprocess metodu)
#----------------------------------------------------
async def email_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        email_adresi = context.args[0]
        
        await update.message.reply_text(f"🔍 {email_adresi} için hesaplar aranıyor... Bu işlem 1 dakika kadar sürebilir, lütfen bekleyin.")

        # --- Komutun tam yolunu bul (Sherlock'taki gibi) ---
        venv_bin_dir = os.path.dirname(sys.executable)
        holehe_command_path = os.path.join(venv_bin_dir, 'holehe')

        # --- 'holehe <email> --no-color' komutunu çalıştır ---
        proc = await asyncio.create_subprocess_exec(
            holehe_command_path,
            email_adresi,
            '--no-color',  # Renk kodları olmadan temiz çıktı almak için
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_data, stderr_data = await proc.communicate()

        if proc.returncode == 0:
            # Başarılı, şimdi text çıktısını ayıkla
            output_lines = stdout_data.decode().split('\n')
            found_accounts = []
            for line in output_lines:
                if line.strip().startswith('[+]'): # [+] ile başlayan satırlar bulunan hesaplardır
                    # '[+] Spotify: https://...' kısmından sadece 'Spotify: https://...' al
                    found_accounts.append(line.strip()[4:]) 
            
            if found_accounts:
                mesaj = f"✅ **Bulunan Hesaplar ({email_adresi}):**\n\n"
                mesaj += "\n".join(found_accounts)
            else:
                mesaj = f"ℹ️ **Sonuç Bulunamadı**\n\n`{email_adresi}` adresi için hesap bulunamadı."
        
        else:
            mesaj = f"Hata: holehe aracı çalıştırılamadı.\n{stderr_data.decode()}"

        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        await update.message.reply_text("Kullanım: /email <email@adres.com>")
    except Exception as e:
        print(f"holehe genel hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")





#----------------------------------------------------
# YENİ USERNAME FONKSİYONU (Sherlock) - GENİŞ LİSTE
#----------------------------------------------------
async def username_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        username = context.args[0]
        
        await update.message.reply_text(f"🔍 {username} için seçili sitelerde kullanıcı adı aranıyor... Bu işlem 1-2 dakika sürebilir, lütfen bekleyin.")

        # Sherlock komutunun venv içindeki tam yolunu bul
        venv_bin_dir = os.path.dirname(sys.executable)
        sherlock_command_path = os.path.join(venv_bin_dir, 'sherlock')

        # Sherlock'u 'sherlock' olarak değil, tam yoluyla çağır
        # SADECE SEÇTİĞİMİZ POPÜLER SİTELERDE ARASIN (Genişletilmiş Liste)
        proc = await asyncio.create_subprocess_exec(
            sherlock_command_path,
            username,
            '--json',
            '-',
            '--site', 'reddit',
            '--site', 'instagram',
            '--site', 'facebook',
            '--site', 'linkedin',
            '--site', 'youtube',
            '--site', 'pinterest',
            '--site', 'tiktok',
            '--site', 'twitter',      # (X için)
            '--site', 'snapchat',
            '--site', 'twitch',
            '--site', 'tinder',
            '--site', 'vk',
            '--site', 'ebay',
            '--site', 'amazon',
            '--site', 'spotify',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Sürecin bitmesini bekle ve çıktıları al
        stdout_data, stderr_data = await proc.communicate()

        if proc.returncode == 0:
            # Başarılı
            try:
                # JSON çıktısını işle
                # Sherlock bazen JSON olmayan satırlar basabilir, sadece JSON kısmını al
                json_output = stdout_data.decode().split('{', 1)[1].rsplit('}', 1)[0]
                results = json.loads("{" + json_output + "}")
                
                found_accounts = []
                for site, data in results.items():
                    if data.get("status") == "claimed": # 'claimed' (bulundu) olanları al
                        found_accounts.append(f"{site}: {data.get('url')}")
                
                if found_accounts:
                    mesaj = f"✅ **Bulunan Hesaplar ({username}):**\n\n"
                    # Listeyi alt alta güzelce sırala
                    mesaj += "\n".join(found_accounts)
                else:
                    mesaj = f"ℹ️ **Sonuç Bulunamadı**\n\n`{username}` adı için bilinen sitelerde hesap bulunamadı."
                        
            except (json.JSONDecodeError, IndexError):
                mesaj = "Hata: Sherlock'tan gelen JSON verisi işlenemedi."
                print(f"Sherlock JSON Hatası: {stdout_data.decode()}")

        else:
            # Sherlock hata verdi
            mesaj = f"Hata: Sherlock aracı çalıştırılamadı.\n{stderr_data.decode()}"

        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        await update.message.reply_text("Kullanım: /username <kullaniciadi>")
    except Exception as e:
        print(f"Sherlock genel hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")




# ... (tüm diğer /username fonksiyonunuz burada bitiyor) ...


# --------------------------------------------
# BU FONKSİYONUN TAMAMI EN SOLDA (GİRİNTİSİZ) OLMALI
# --------------------------------------------
async def post_init(application: Application):
    """Bot başladığında komut menüsünü ayarlar."""
    
    # BU SATIRLAR 4 BOŞLUK İÇERİDE
    commands = [
        BotCommand("start", "Botu başlatır ve merhaba der"),
        BotCommand("ip", "IP adresi sorgular (Örn: /ip 8.8.8.8)"),
        BotCommand("domain", "Domain sorgular (Örn: /domain google.com)"),
        BotCommand("email", "Email ile hesap arar (Örn: /email test@test.com)"),
        BotCommand("username", "Kullanıcı adı arar (Örn: /username test)")
    ]
    
    # BU SATIR DA 4 BOŞLUK İÇERİDE
    await application.bot.set_my_commands(commands)


# --------------------------------------------
# BU FONKSİYON DA EN SOLDA (GİRİNTİSİZ) OLMALI
# --------------------------------------------
def main():
    # BU SATIRLAR 4 BOŞLUK İÇERİDE
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ip", ip_sorgula))
    application.add_handler(CommandHandler("domain", domain_sorgula))
    application.add_handler(CommandHandler("email", email_sorgula))
    application.add_handler(CommandHandler("username", username_sorgula))

    print("Bot çalışıyor... (Durdurmak için CTRL+C)")
    application.run_polling()


# --------------------------------------------
# BU 'if' BLOĞU DA EN SOLDA (GİRİNTİSİZ) OLMALI
# --------------------------------------------
if __name__ == "__main__":
    # BU SATIR 4 BOŞLUK İÇERİDE
    main()
