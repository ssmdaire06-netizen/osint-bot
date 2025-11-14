# --------------------------------------------------
# GEREKLİ KÜTÜPHANELERİ İÇE AKTARMA (IMPORT)
# --------------------------------------------------
from dotenv import load_dotenv
load_dotenv() # .env dosyasındaki API anahtarlarını yükler

import requests
import os
import whois
import datetime
import asyncio
import json
import sys
import base64
import io

# Telegram Kütüphaneleri
from telegram import Update, BotCommand
from telegram.helpers import escape_markdown
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
    CallbackQueryHandler
)

# Fotoğraf İşleme Kütüphaneleri
from PIL import Image, ExifTags

# API Kütüphaneleri
from shodan import Shodan


# --------------------------------------------------
# API ANAHTARLARINI YÜKLEME
# --------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
IPINFO_API_TOKEN = os.environ.get("IPINFO_API_TOKEN")
VT_API_TOKEN = os.environ.get("VT_API_TOKEN")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")


# --------------------------------------------------
# YARDIMCI FONKSİYONLAR (EXIF için)
# --------------------------------------------------
def get_decimal_from_dms(dms, ref):
    """GPS verisini (Derece, Dakika, Saniye) ondalık (decimal) formata çevirir."""
    try:
        degrees = dms[0]
        minutes = dms[1] / 60.0
        seconds = dms[2] / 3600.0
        
        val = degrees + minutes + seconds
        if ref in ['S', 'W']: # Güney ve Batı negatif olmalı
            val = -val
        return val
    except:
        return None

def process_exif_sync(file_bytes_io):
    """Bu fonksiyon, botu DONDURUR, bu yüzden 'to_thread' ile çağrılmalıdır."""
    
    print("--- DEBUG 3: (Thread) Dosya Pillow(Image.open) ile açılıyor... ---")
    image = Image.open(file_bytes_io)
    
    print("--- DEBUG 4: (Thread) Dosya açıldı. EXIF verisi çekiliyor... ---")
    exif_data_raw = image.getexif()

    if not exif_data_raw:
        print("--- DEBUG 5.A: (Thread) EXIF Verisi Boş. ---")
        return None, "NO_EXIF"

    exif_data = {}
    for tag, value in exif_data_raw.items():
        tag_name = ExifTags.TAGS.get(tag, tag)
        exif_data[tag_name] = value

    mesaj_parcalari = {}
    found = False

    if "Make" in exif_data and exif_data["Make"]:
        mesaj_parcalari["Make"] = exif_data['Make']
        found = True
    if "Model" in exif_data and exif_data["Model"]:
        mesaj_parcalari["Model"] = exif_data['Model']
        found = True
    if "DateTimeOriginal" in exif_data and exif_data["DateTimeOriginal"]:
        mesaj_parcalari["DateTimeOriginal"] = exif_data['DateTimeOriginal']
        found = True
    
    gps_info_raw = exif_data.get("GPSInfo")
    if gps_info_raw:
        gps_tags = {}
        for tag, value in gps_info_raw.items():
            tag_name = ExifTags.GPSTAGS.get(tag, tag)
            gps_tags[tag_name] = value
        
        lat_dms = gps_tags.get("GPSLatitude")
        lat_ref = gps_tags.get("GPSLatitudeRef")
        lon_dms = gps_tags.get("GPSLongitude")
        lon_ref = gps_tags.get("GPSLongitudeRef")

        if lat_dms and lat_ref and lon_dms and lon_ref:
            lat = get_decimal_from_dms(lat_dms, lat_ref)
            lon = get_decimal_from_dms(lon_dms, lon_ref)
            if lat is not None and lon is not None:
                mesaj_parcalari["GPSLatitude"] = lat
                mesaj_parcalari["GPSLongitude"] = lon
                found = True

    if not found and not gps_info_raw:
        print("--- DEBUG 5.B: (Thread) Önemli veri yok. ---")
        return None, "NOT_FOUND"

    print("--- DEBUG 5.C: (Thread) EXIF Verisi dolu. ---")
    return mesaj_parcalari, "FOUND"


# --------------------------------------------------
# ANA KOMUT FONKSİYONLARI
# --------------------------------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/start komutu: Kullanıcıyı statik yardım menüsüyle karşılar."""
    user_name = update.effective_user.first_name
    
    # --- YENİ KARŞILAMA METNİ (SİZİN İSTEDİĞİNİZ GİBİ) ---
    mesaj = f"Selam {user_name}! 🚀 Kişisel OSINT asistanınıza hoş geldiniz.\n\n"
    mesaj += "İşte yapabileceklerim:\n\n"
    
    mesaj += "🎣 `/url <https://link.com>`\n"
    mesaj += "   _URL/Link Güvenlik Kontrolü (VirusTotal)_\n\n"
    
    mesaj += "🌐 `/domain <domain.com>`\n"
    mesaj += "   _Domain Bilgileri (Whois & DNS Kayıtları)_\n\n"
    
    mesaj += "📍 `/ip <IP Adresi>`\n"
    mesaj += "   _IP Adresi Analizi (Konum, ISP, vb.)_\n\n"
    
    mesaj += "🔌 `/shodan <IP Adresi>`\n"
    mesaj += "   _Pasif Port Tarama (Shodan Servisleri)_\n\n"
    
    mesaj += "🗄️ `/ara <terim>`\n"
    mesaj += "   _Özel Veritabanı Sorgulama (JSON)_\n\n"

    mesaj += "📧 `/email <e-posta@adres.com>`\n"
    mesaj += "   _E-posta Analizi (Hangi sitelere kayıtlı?)_\n\n"

    mesaj += "📸 `(Bana bir fotoğrafı 'Dosya' olarak atın)`\n"
    mesaj += "   _Fotoğrafın gizli meta (EXIF) verilerini analiz ederim._\n\n"
    
    mesaj += "Bir komutun kullanımı hakkında detaylı bilgi için, o komutu tek başına yazın (örn: `/ip` yazıp gönderin)."
    
    # Artık buton (ReplyMarkup) göndermiyoruz
    await update.message.reply_text(mesaj, parse_mode='Markdown')


async def ip_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ip komutu: IP Adresi Analizi (IPinfo)"""
    try:
        # Komutla birlikte argüman (IP) gelip gelmediğini kontrol et
        ip_adresi = context.args[0]
        
        # --- (Mevcut kodunuz devam ediyor) ---
        api_url = f"https://ipinfo.io/{ip_adresi}/json?token={IPINFO_API_TOKEN}"
        
        response = requests.get(api_url)
        
        if response.status_code == 200:
            data = response.json()
            
            mesaj = f"🔍 **IP Sorgu Sonucu: {data.get('ip')}**\n\n"
            mesaj += f"📍 Konum: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}\n"
            mesaj += f"🏢 Organizasyon: {data.get('org', 'N/A')}\n"
            mesaj += f"🗺️ Koordinatlar: {data.get('loc', 'N/A')}\n"
            
            if data.get('loc'):
                mesaj += f"🌍 [Google Maps](http://googleusercontent.com/maps/google.com/1{data.get('loc')})"
            
            await update.message.reply_text(mesaj, parse_mode='Markdown')
        else:
            await update.message.reply_text(f"API hatası: {response.status_code}")
            
    except IndexError:
        # --- YENİ DETAYLI YARDIM MESAJI ---
        # Eğer /ip tek başına yazılırsa (argüman yoksa) burası çalışır
        mesaj = (
            "📍 **IP Analizi Komutu**\n\n"
            "Bu komut, bir IP adresinin coğrafi konumunu, sahibini (ISP) ve koordinatlarını sorgular.\n\n"
            "**Kullanım:**\n`/ip <IP_ADRESİ>`\n\n"
            "**Örnek:**\n`/ip 8.8.8.8`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"Bir hata oluştu: {str(e)}")


async def domain_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/domain komutu: Domain Bilgileri (Whois & DNS)"""
    try:
        domain_adi = context.args[0]
        await update.message.reply_text(f"🔍 {domain_adi} için bilgiler sorgulanıyor... Lütfen bekleyin.")

        whois_mesaj = "--- WHOIS BİLGİSİ ---\n"
        try:
            w = whois.whois(domain_adi)
            
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

        dns_mesaj = "\n--- DNS KAYITLARI ---\n"
        try:
            a_response = requests.get(f"https://dns.google/resolve?name={domain_adi}&type=A")
            a_data = a_response.json()
            if a_data.get('Answer'):
                a_record = a_data['Answer'][0]['data']
                dns_mesaj += f"A Kaydı (IP): {a_record}\n"
            else:
                dns_mesaj += "A Kaydı (IP): Bulunamadı.\n"
            
            mx_response = requests.get(f"https://dns.google/resolve?name={domain_adi}&type=MX")
            mx_data = mx_response.json()
            if mx_data.get('Answer'):
                mx_records = [item['data'].split(' ')[1] for item in mx_data['Answer']]
                dns_mesaj += f"MX Kayıtları (Mail): {', '.join(mx_records)}\n"
            else:
                dns_mesaj += "MX Kayıtları (Mail): Bulunamadı.\n"
                
        except Exception:
            dns_mesaj += "DNS kayıtları sorgulanamadı.\n"

        mesaj = f"📄 **Domain Sorgu Sonucu: {domain_adi}**\n\n"
        mesaj += whois_mesaj
        mesaj += dns_mesaj
        
        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        # --- YENİ DETAYLI YARDIM MESAJI ---
        mesaj = (
            "🌐 **Domain Analizi Komutu**\n\n"
            "Bu komut, bir alan adının sahibini (Whois) ve teknik (DNS) kayıtlarını gösterir.\n\n"
            "**Kullanım:**\n`/domain <domain.com>`\n\n"
            "**Örnek:**\n`/domain btk.gov.tr`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")


async def email_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/email komutu: E-posta Analizi (holehe)"""
    try:
        email_adresi = context.args[0]
        
        await update.message.reply_text(f"🔍 {email_adresi} için hesaplar aranıyor... Bu işlem 1 dakika kadar sürebilir, lütfen bekleyin.")

        venv_bin_dir = os.path.dirname(sys.executable)
        holehe_command_path = os.path.join(venv_bin_dir, 'holehe')

        proc = await asyncio.create_subprocess_exec(
            holehe_command_path,
            email_adresi,
            '--no-color',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_data, stderr_data = await proc.communicate()

        if proc.returncode == 0:
            output_lines = stdout_data.decode().split('\n')
            found_accounts = []
            for line in output_lines:
                if line.strip().startswith('[+]'):
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
        # --- YENİ DETAYLI YARDIM MESAJI ---
        mesaj = (
            "📧 **E-posta Analizi Komutu**\n\n"
            "Bu komut, bir e-posta adresinin hangi popüler sitelere (Instagram, Spotify vb.) kayıtlı olduğunu bulur.\n\n"
            "**Kullanım:**\n`/email <email@adres.com>`\n\n"
            "**Örnek:**\n`/email test@example.com`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        print(f"holehe genel hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")


async def url_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/url komutu: URL Güvenlik Kontrolü (VirusTotal)"""
    try:
        url = context.args[0]
        
        if not VT_API_TOKEN:
            await update.message.reply_text("Hata: Sunucu tarafında VT_API_TOKEN ayarlanmamış.")
            return

        await update.message.reply_text(f"🔍 {url} VirusTotal'da analiz ediliyor... Lütfen bekleyin.")

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
        # --- YENİ DETAYLI YARDIM MESAJI ---
        mesaj = (
            "🎣 **URL Güvenlik Kontrolü (VirusTotal)**\n\n"
            "Bir web sitesinin (URL) güvenli olup olmadığını 70+ antivirüs motorunda tarar.\n\n"
            "**Kullanım:**\n`/url <https://ornek.com>`\n\n"
            "**Örnek:**\n`/url google.com`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        print(f"URL Sorgulama Hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")


async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Fotoğraf ve Dosya olarak gönderilen resimleri işler (EXIF)."""
    try:
        print("--- DEBUG 1: 'handle_image' fonksiyonu başladı. ---")
        await update.message.reply_text("📸 Görüntü alınıyor ve EXIF verileri analiz ediliyor...")
        
        file_id = None
        file_name = "image.jpg"

        if update.message.photo:
            file_id = update.message.photo[-1].file_id
        elif update.message.document and update.message.document.mime_type.startswith('image/'):
            file_id = update.message.document.file_id
            file_name = escape_markdown(update.message.document.file_name, version=2)
        else:
            await update.message.reply_text("Bu dosya formatı desteklenmiyor.")
            return

        print(f"--- DEBUG 2: Dosya ID alındı ({file_id}). Hafızaya indiriliyor... ---")
        photo_file = await context.bot.get_file(file_id)
        f = io.BytesIO()
        await photo_file.download_to_memory(f)
        f.seek(0)
        
        print("--- DEBUG 3: Dondurucu işlem (process_exif_sync) 'to_thread' ile başlatılıyor... ---")
        sonuclar, durum = await asyncio.to_thread(process_exif_sync, f)
        print(f"--- DEBUG 4: 'to_thread' bitti. Durum: {durum} ---")

        if durum == "NO_EXIF":
            mesaj = f"ℹ️ **EXIF Verisi Bulunamadı** ({file_name})\n\n"
            if update.message.photo:
                mesaj += "Sebep: Resmi 'Fotoğraf olarak' gönderdiniz\. Telegram gizlilik için meta verileri siler\.\n"
                mesaj += "**Lütfen resmi 'Dosya olarak' \(Sıkıştırılmamış\) göndermeyi deneyin\.**"
            else:
                mesaj += "Sebep: Bu dosyanın orijinalinde meta veri olmayabilir \(örn: WhatsApp'tan gelen, ekran görüntüsü vb\.\)\."
            await update.message.reply_text(mesaj, parse_mode='MarkdownV2')
            return

        if durum == "NOT_FOUND":
            mesaj = f"📊 **Fotoğraf Meta Veri \(EXIF\) Analizi** \({file_name}\)\n\n"
            mesaj += "Cihaz modeli, tarih veya GPS gibi önemli bir veri bulunamadı\."
            await update.message.reply_text(mesaj, parse_mode='MarkdownV2')
            return
            
        if durum == "FOUND":
            mesaj = f"📊 **Fotoğraf Meta Veri \(EXIF\) Analizi** \({file_name}\)\n\n"
            if sonuclar.get("Make"):
                mesaj += f"Cihaz Markası: {escape_markdown(sonuclar['Make'], version=2)}\n"
            if sonuclar.get("Model"):
                mesaj += f"Cihaz Modeli: {escape_markdown(sonuclar['Model'], version=2)}\n"
            if sonuclar.get("DateTimeOriginal"):
                mesaj += f"Cihaz Tarihi: {escape_markdown(sonuclar['DateTimeOriginal'], version=2)}\n"
            
            if sonuclar.get("GPSLatitude"):
                lat = sonuclar["GPSLatitude"]
                lon = sonuclar["GPSLongitude"]
                mesaj += f"\n📍 **GPS KONUMU BULUNDU\!**\n"
                mesaj += f"Enlem: {escape_markdown(str(lat), version=2)}\n"
                mesaj += f"Boylam: {escape_markdown(str(lon), version=2)}\n"
                mesaj += f"[Google Maps](http://googleusercontent.com/maps/google.com/1{lat},{lon})\n"
            
            await update.message.reply_text(mesaj, parse_mode='MarkdownV2')

    except Exception as e:
        print(f"\n\n!!!! HATA YAKALANDI (handle_image) !!!!")
        print(f"HATA TÜRÜ: {type(e)}")
        print(f"HATA MESAJI: {str(e)}")
        print("!!!! ---------------------------- !!!!\n\n")
        
        error_message = escape_markdown(str(e), version=2)
        await update.message.reply_text(f"Bir hata oluştu: Fotoğraf işlenemedi\. \(Format desteklenmiyor veya dosya bozuk\)\nDetay: {error_message}", parse_mode='MarkdownV2')


async def ara_json(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ara komutu: Özel JSON Veritabanını (Turkey.json) sorgular."""
    try:
        arama_terimi = " ".join(context.args).lower()
        if not arama_terimi:
            raise IndexError("Arama terimi girilmedi")
        
        await update.message.reply_text(f"🔍 '{arama_terimi}' veritabanında aranıyor...")

        dosya_adi = 'Turkey.json'
        
        with open(dosya_adi, 'r', encoding='utf-8') as f:
            data = json.load(f)

        sonuclar = []
        for kayit in data:
            bulundu = False
            
            adi = str(kayit.get("adi", "")).lower()
            soyadi = str(kayit.get("soyadi", "")).lower()
            gsm = str(kayit.get("gsm", "")).lower()
            cihaz = str(kayit.get("cihaz", "")).lower()
            
            tam_isim = (adi + " " + soyadi).strip()

            if (arama_terimi in tam_isim) or \
               (arama_terimi in gsm) or \
               (arama_terimi in cihaz):
                bulundu = True
            
            if bulundu:
                kayit_str = f"--- BULUNAN KAYIT ---\n"
                
                isim_soyisim = f"{kayit.get('adi', '')} {kayit.get('soyadi', '')}".strip()
                if isim_soyisim:
                     kayit_str += f"İsim: {isim_soyisim}\n"
                
                if kayit.get("gsm"):
                    kayit_str += f"Gsm: {kayit.get('gsm')}\n"
                
                if kayit.get("cihaz"):
                    kayit_str += f"Cihaz: {kayit.get('cihaz')}\n"
                     
                sonuclar.append(kayit_str)

        if sonuclar:
            mesaj = f"✅ **'{arama_terimi}' için {len(sonuclar)} sonuç bulundu:**\n\n"
            mesaj += "\n\n".join(sonuclar) 
        else:
            mesaj = f"ℹ️ **Sonuç Bulunamadı**\n\n`{arama_terimi}` terimi '{dosya_adi}' içinde bulunamadı."
            
        if len(mesaj) > 4096:
            mesaj = f"✅ **Çok fazla sonuç bulundu!** (Toplam {len(sonuclar)} adet). Mesaj limitini aşmamak için ilk 10 sonuç gösteriliyor:\n\n" + "\n\n".join(sonuclar[:10])

        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except FileNotFoundError:
        await update.message.reply_text(f"Hata: '{dosya_adi}' dosyası sunucuda bulunamadı.")
    except json.JSONDecodeError:
        await update.message.reply_text(f"Hata: '{dosya_adi}' dosyasının formatı bozuk (Geçerli bir JSON değil). Lütfen tırnak ve virgülleri kontrol edin.")
    except IndexError:
        # --- YENİ DETAYLI YARDIM MESAJI ---
        mesaj = (
            "🗄️ **Özel Veritabanı Arama Komutu**\n\n"
            "Bu komut, `Turkey.json` dosyanızda 'İsim', 'Gsm' veya 'Cihaz' bilgisi arar.\n\n"
            "**Kullanım:**\n`/ara <Aranacak Terim>`\n\n"
            "**Örnekler:**\n`/ara Ahmet Yılmaz`\n`/ara 5551234455`\n`/ara iPhone 14`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        print(f"JSON Arama Hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")


async def shodan_sorgula(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/shodan komutu: Pasif Port Tarama (Shodan)"""
    try:
        ip_adresi = context.args[0]
        
        if not SHODAN_API_KEY:
            await update.message.reply_text("Hata: Sunucu tarafında SHODAN_API_KEY ayarlanmamış.")
            return

        await update.message.reply_text(f"🔍 {ip_adresi} için Shodan pasif port taraması yapılıyor...")

        mesaj = f"**Shodan Raporu ({ip_adresi})**\n\n"
        
        try:
            api = Shodan(SHODAN_API_KEY)
            
            print("--- DEBUG: Shodan sorgusu 'to_thread' ile başlatılıyor... ---")
            host_info = await asyncio.to_thread(api.host, ip_adresi)
            print("--- DEBUG: Shodan sorgusu tamamlandı. ---")
            
            ports = host_info.get("ports", [])
            if not ports:
                mesaj += "ℹ️ Bu IP için bilinen açık port/servis bulunamadı."
                await update.message.reply_text(mesaj, parse_mode='Markdown')
                return

            mesaj += "Bulunan açık portlar:\n```\n"
            mesaj += ", ".join(map(str, ports)) # Portları tek satırda göster
            mesaj += "\n```\n\n"
            
            mesaj += "Detaylı Servis Bilgileri:\n"
            for item in host_info.get("data", []):
                port = item.get('port', 'N/A')
                service = item.get('product', 'Bilinmiyor')
                transport = item.get('transport', 'tcp') # tcp/udp
                mesaj += f"Port {port}/{transport}: {service}\n"

        except Exception as api_error:
            mesaj = f"API Hatası: {str(api_error)}"

        await update.message.reply_text(mesaj, parse_mode='Markdown')

    except IndexError:
        # --- YENİ DETAYLI YARDIM MESAJI ---
        mesaj = (
            "🔌 **Port Tarama (Shodan) Komutu**\n\n"
            "Bu komut, bir IP adresindeki açık portları ve o portlarda çalışan servisleri (örn: web sunucusu, veritabanı) pasif olarak tarar.\n\n"
            "**Kullanım:**\n`/shodan <IP_ADRESİ>`\n\n"
            "**Örnek:**\n`/shodan 1.1.1.1`"
        )
        await update.message.reply_text(mesaj, parse_mode='Markdown')
    except Exception as e:
        print(f"Shodan Hatası: {str(e)}")
        await update.message.reply_text(f"Genel bir hata oluştu: {str(e)}")


#----------------------------------------------------
# BOT AYARLARI VE BAŞLATMA
#----------------------------------------------------

async def post_init(application: Application):
    """Bot başladığında komut menüsünü (/) ayarlar."""
    
    commands = [
        BotCommand("start", "👋 Ana menüyü ve komut listesini gösterir."),
        
        # --- Bölüm 1: Site Tarama ---
        BotCommand("url", "🎣 URL/Link Güvenlik Kontrolü (VirusTotal)"),
        BotCommand("domain", "🌐 Domain Bilgileri (Whois & DNS Kayıtları)"),
        BotCommand("ip", "📍 IP Adresi Analizi (Konum, ISP, vb.)"),
        BotCommand("shodan", "🔌 Pasif Port Tarama (Shodan)"),

        # --- Bölüm 2: Arama ---
        BotCommand("ara", "🗄️ Özel Veritabanı Sorgulama (JSON)"),
        BotCommand("email", "📧 E-posta Analizi (Hangi sitelere kayıtlı?)")
    ]
    
    await application.bot.set_my_commands(commands)


def main():
    """Botu başlatır ve tüm komutları (handler) kaydeder."""
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    # --- BÖLÜM 1: / (SLASH) KOMUTLARI ---
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ip", ip_sorgula))
    application.add_handler(CommandHandler("domain", domain_sorgula))
    application.add_handler(CommandHandler("email", email_sorgula))
    application.add_handler(CommandHandler("url", url_sorgula))
    application.add_handler(CommandHandler("shodan", shodan_sorgula))
    application.add_handler(CommandHandler("ara", ara_json))
    
    # --- BÖLÜM 2: BUTON VEYA DOSYA YAKALAYICILAR ---
    
    # /start komutundaki 'inline' butonlarını yakalar    
    # Fotoğraf ve Dosya olarak gönderilen resimleri yakalar
    application.add_handler(MessageHandler(filters.PHOTO, handle_image))
    application.add_handler(MessageHandler(filters.Document.IMAGE, handle_image))
    
    print("Bot çalışıyor... (Durdurmak için CTRL+C)")
    application.run_polling()


if __name__ == "__main__":
    main()
