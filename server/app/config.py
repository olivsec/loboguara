class Config:

    # Secret key for session management and security
    SECRET_KEY = 'YOUR_SECRET_KEY_HERE'

    # PostgreSQL Configuration
    SQLALCHEMY_DATABASE_URI = 'postgresql://guarauser:YOUR_PASSWORD_HERE@localhost/guaradb?sslmode=disable'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email settings - Required for two-factor authentication (2FA) via email and notifications sent by the featur>
    MAIL_SERVER = 'smtp.exemple.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'no-reply@exemple.com'
    MAIL_PASSWORD = 'YOUR_SMTP_PASSWORD_HERE'
    MAIL_DEFAULT_SENDER = 'no-reply@exemple.com'

    # Allowed domains for Link Tracking functionality
    ALLOWED_DOMAINS = [
        'yourdomain1.my.id',
        'yourdomain2.com',
        'yourdomain3.net'
    ]

    # API access settings for Lobo Guara - Required for SSL Certificate Search, Data Leak Alerts, URL User Pass, a>
    API_ACCESS_TOKEN = 'YOUR_LOBOGUARA_API_TOKEN_HERE'
    API_URL = 'https://loboguara.olivsec.com.br/api'

    # Path to Chrome and ChromeDriver binaries
    CHROME_DRIVER_PATH = '/opt/loboguara/bin/chromedriver'
    GOOGLE_CHROME_PATH = '/opt/loboguara/bin/google-chrome'

    # Path to FFUF binary
    FFUF_PATH = '/opt/loboguara/bin/ffuf'

    # Path to Subfinder binary
    SUBFINDER_PATH = '/opt/loboguara/bin/subfinder'

    # Logs configuration
    LOG_LEVEL = 'ERROR'
    LOG_FILE = '/opt/loboguara/logs/loboguara.log'
