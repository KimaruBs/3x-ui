env = """BOT_TOKEN=token
PAYMENT_TOKEN='39054xxxx:LIVE:45xxx' # payment token from @BotFather
ADMINS=123456789
XUI_API_URL=http://1.11.111.1:5000/wV20Y2nooIFI5TBblY
XUI_HOST=1.11.111.1
XUI_BASE_PATH=/panel
XUI_SERVER_NAME=burmalda
XUI_USERNAME=admin
XUI_PASSWORD=2000
XUI_API_TOKEN=token
XUI_SUB_PORT=2096
SUBSCRIPTION_URL_BASE=1.11.111.1
XUI_VERIFY_SSL=False
INBOUND_ID=1
REALITY_PUBLIC_KEY=pubkey_reality
REALITY_FINGERPRINT=chrome
REALITY_SNI=teamdocs.su
REALITY_SHORT_ID=short_id_reality
# Временные профили (30 минут)
TEMP_INBOUND_ID=2
TEMP_REALITY_PUBLIC_KEY=pubkey_reality_temp
TEMP_REALITY_FINGERPRINT=chrome
TEMP_REALITY_SNI=teamdocs.su
TEMP_REALITY_SHORT_ID=short_id_reality_temp
TEMP_REALITY_SPIDER_X=/
TEMP_WEB_SERVER_PORT=8080
# SSL сертификаты для HTTPS
TEMP_SSL_CERT_PATH=/path/to/fullchain.pem
TEMP_SSL_KEY_PATH=/path/to/privkey.pem
"""
def create_env():
	with open(".env", "w", encoding='utf-8') as file:
		file.write(env)
