from dotenv import load_dotenv
load_dotenv()

import requests
import os
import whois 
import datetime
import asyncio
import json 
import sys
import base64
from telegram import Update, BotCommand
from telegram.ext import Application, CommandHandler, ContextTypes


TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
IPINFO_API_TOKEN = os.environ.get("IPINFO_API_TOKEN")
VT_API_TOKEN = os.environ.get("VT_API_TOKEN")



#----------------------------------------------------
# YENİ VE ETKİLEYİCİ START KOMUTU
#----------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Kullanıcının adını alarak onu selamlayalım
    user_name = update.effective_user.first_name
    
    mesaj = f"Selam {user_name}! 🚀 Ben sizin kişisel OSINT (Açık Kaynak İstihbarat) asistanınızım.\n\n"
    mesaj += "Dijital dünyadaki izleri takip etmenize yardımcı olmak için buradayım.\n\n"
    mesaj += "**İşte yapabileceklerim:**\n\n"
    
    mesaj += "📍 `/ip <IP Adresi>`\n"
    mesaj += "   _IP Adresi Analizi (Konum, ISP, vb.)_\n\n"
    
    mesaj += "🌐 `/domain <domain.com>`\n"
    mesaj += "   _Domain Bilgileri (Whois & DNS Kayıtları)_\n\n"
    
    mesaj += "📧 `/email <e-posta@adres.com>`\n"
    mesaj += "   _E-posta Analizi (Hangi sitelere kayıtlı?)_\n\n"
    
    mesaj += "🧑‍💻 `/username <kullaniciadi>`\n"
    mesaj += "   _Kullanıcı Adı Arama (Sosyal Medya vb.)_\n\n"
    
    mesaj += "🗄️ `/ara <terim>`\n"
    mesaj += "   _Özel Veritabanı Sorgulama (İsim, Tel, vb.)_\n\n"
    
    mesaj += "🎣 `/url <https://link.com>`\n"
    mesaj += "   _URL/Link Güvenlik Kontrolü (VirusTotal)_\n\n"
    
    mesaj += "Tüm komutları görmek için / tuşuna basmanız yeterli."

    # Görsellik (Markdown) için parse_mode'u ekliyoruz
    await update.message.reply_text(mesaj, parse_mode='Markdown')




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
        await update.message.reply_text("Kullanım: /ip IP_ADRESİ")
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
        await update.message.reply_text("Kullanım: /domain domain.com")
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
        await update.message.reply_text("Kullanım: /email email@adres.com")
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
        await update.message.reply_text("Kullanım: /username kullaniciadi")
    except Exception as e:
        print(f"Sherlock genel hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")





#----------------------------------------------------
# YENİ URL SORGULAMA FONKSİYONU (VirusTotal)
#----------------------------------------------------
async def url_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        url = context.args[0]
        
        if not VT_API_TOKEN:
            await update.message.reply_text("Hata: Sunucu tarafında VT_API_TOKEN ayarlanmamış.")
            return

        await update.message.reply_text(f"🔍 {url} VirusTotal'da analiz ediliyor... Lütfen bekleyin.")

        # VT API v3, URL'nin base64 enkodlanmış halini 'id' olarak kullanır
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": VT_API_TOKEN}
        
        try:
            response = requests.get(api_url, headers=headers)
        except requests.exceptions.RequestException as e:
            await update.message.reply_text(f"API bağlantı hatası: {e}")
            return

        mesaj = ""
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            
            sonuc_text = "Bilinmiyor"
            if malicious > 0:
                sonuc_text = f"❌ ZARARLI ({malicious} motor)"
            elif suspicious > 0:
                sonuc_text = f"⚠️ ŞÜPHELİ ({suspicious} motor)"
            elif harmless > 0:
                sonuc_text = f"✅ GÜVENLİ ({harmless} motor)"

            mesaj = f"**VirusTotal Raporu ({url})**\n\n"
            mesaj += f"**Sonuç: {sonuc_text}**\n\n"
            mesaj += f"Zararlı: {malicious}\n"
            mesaj += f"Şüpheli: {suspicious}\n"
            mesaj += f"Güvenli: {harmless}\n"
            
            first_seen = data.get("first_submission_date")
            if first_seen:
                mesaj += f"\nİlk Görülme: {datetime.datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d')}"

        elif response.status_code == 404:
            mesaj = "ℹ️ Bu URL VirusTotal veritabanında bulunamadı. (Daha önce taranmamış olabilir)."
        elif response.status_code == 401:
            mesaj = "API Hatası: VirusTotal API Token'ı geçersiz veya yetkisiz."
        else:
            mesaj = f"API Hatası: {response.status_code} - {response.text}"

        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        await update.message.reply_text("Kullanım: /url https://ornek.com")
    except Exception as e:
        print(f"URL Sorgulama Hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")



# ... (tüm diğer /username fonksiyonunuz burada bitiyor) ...


# --------------------------------------------
# BU FONKSİYONUN TAMAMI EN SOLDA (GİRİNTİSİZ) OLMALI
# --------------------------------------------
#----------------------------------------------------
# BOT BAŞLADIĞINDA MENÜYÜ AYARLAYAN FONKSİYON
#----------------------------------------------------
async def post_init(application: Application):
    """Bot başladığında komut menüsünü ayarlar."""
    
    # Yeni ve daha açıklayıcı komut listesi
    commands = [
        BotCommand("start", "👋 Botu başlatır ve komutları listeler."),
        BotCommand("ip", "📍 IP Adresi Analizi (Konum, ISP, vb.)"),
        BotCommand("domain", "🌐 Domain Bilgileri (Whois & DNS Kayıtları)"),
        BotCommand("email", "📧 E-posta Analizi (Hangi sitelere kayıtlı?)"),
        BotCommand("username", "🧑‍💻 Kullanıcı Adı Arama (Sosyal Medya vb.)"),
        BotCommand("ara", "🗄️ Özel Veritabanı Sorgulama (İsim, Tel, vb.)"),
        BotCommand("url", "🎣 URL/Link Güvenlik Kontrolü (VirusTotal)")
    ]
    
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
    application.add_handler(CommandHandler("url", url_sorgula))


    print("Bot çalışıyor... (Durdurmak için CTRL+C)")
    application.run_polling()


# --------------------------------------------
# BU 'if' BLOĞU DA EN SOLDA (GİRİNTİSİZ) OLMALI
# --------------------------------------------
if __name__ == "__main__":
    # BU SATIR 4 BOŞLUK İÇERİDE
    main()
