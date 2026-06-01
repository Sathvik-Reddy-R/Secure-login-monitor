import os
from dotenv import load_dotenv

load_dotenv()
class Config:

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change_this_secret_key"
    )

    DB_NAME = "security.db"

    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    MAIL_USERNAME = os.getenv(
        "MAIL_USERNAME"
    )

    MAIL_PASSWORD = os.getenv(
        "MAIL_PASSWORD"
    )

    VIRUSTOTAL_API_KEY = os.getenv(
        "VT_API_KEY"
    )

    ABUSEIPDB_API_KEY = os.getenv(
        "ABUSEIPDB_API_KEY"
    )

    WHITELIST_IPS = [
        "127.0.0.1"
    ]
