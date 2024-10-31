
# Lobo Guará - Cyber Threat Intelligence Platform

**Lobo Guará** is a platform aimed at cybersecurity professionals, with various features focused on Cyber Threat Intelligence (CTI). It offers tools that make it easier to identify threats, monitor data leaks, analyze suspicious domains and URLs, and much more.

## Features

### 1. **SSL Certificate Search**
Allows identifying domains and subdomains that may pose a threat to organizations. SSL certificates issued by trusted authorities are indexed in real-time, and users can search using keywords of 4 or more characters.

**Note**: The current database contains certificates issued from September 5, 2024.

### 2. **SSL Certificate Discovery**
Allows the insertion of keywords for monitoring. When a certificate is issued and the common name contains the keyword (minimum of 5 characters), it will be displayed to the user.

### 3. **Tracking Link**
Generates a link to capture device information from attackers. Useful when the security professional can contact the attacker in some way.

### 4. **Domain Scan**
Performs a scan on a domain, displaying whois information and subdomains associated with that domain.

### 5. **Web Path Scan**
Allows performing a scan on a URL to identify URIs (web paths) related to that URL.

### 6. **URL Scan**
Performs a scan on a URL, generating a screenshot and a mirror of the page. The result can be made public to assist in taking down malicious websites.

### 7. **URL Monitoring**
Monitors a URL with no active application until it returns an HTTP 200 code. At that moment, it automatically initiates a URL scan, providing evidence for actions against malicious sites.

### 8. **Data Leak**
- **Data Leak Alerts**: Monitors and presents almost real-time data leaks posted in hacker forums and websites.
- **URL+User+Password**: Allows searching by URL, username, or password, helping identify leaked data from clients or employees.

### 9. **Threat Intelligence Feeds**
Centralizes intelligence news from various channels, keeping users updated on the latest threats.

## Installation

The application installation has been approved on Ubuntu 24.04 Server and Red Hat 9.4 distributions, the links for which are below:

[Lobo Guará Implementation on Ubuntu 24.04](https://loboguara.olivsec.com.br/docs/lobo_guara_installation_manual_on_Ubuntu_24-04.html)

[Lobo Guará Implementation on Red Hat 9.4](https://loboguara.olivsec.com.br/docs/lobo_guara_installation_manual_on_RedHat_9-4.html)

There is a Dockerfile and a docker-compose version of Lobo Guará too. Just clone the repo and do:

```
docker compose up
```

Then, go to your web browser at localhost:7405.

### Dependencies

Before proceeding with the installation, ensure the following dependencies are installed:

- PostgreSQL
- Python 3.12
- ChromeDriver and Google Chrome (version 129.0.6668.89)
- FFUF (version 2.0.0)
- Subfinder (version 2.6.6)

### Installation Instructions

1. Clone the repository:

```bash
git clone https://github.com/olivsec/loboguara.git
```

2. Enter the project directory:

```bash
cd loboguara/
```

3. Edit the configuration file:

```bash
nano server/app/config.py
```

Fill in the required parameters in the `config.py` file:

```python
class Config:
    SECRET_KEY = 'YOUR_SECRET_KEY_HERE'
    SQLALCHEMY_DATABASE_URI = 'postgresql://guarauser:YOUR_PASSWORD_HERE@localhost/guaradb?sslmode=disable'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'no-reply@example.com'
    MAIL_PASSWORD = 'YOUR_SMTP_PASSWORD_HERE'
    MAIL_DEFAULT_SENDER = 'no-reply@example.com'

    ALLOWED_DOMAINS = ['yourdomain1.my.id', 'yourdomain2.com', 'yourdomain3.net']

    API_ACCESS_TOKEN = 'YOUR_LOBOGUARA_API_TOKEN_HERE'
    API_URL = 'https://loboguara.olivsec.com.br/api'

    CHROME_DRIVER_PATH = '/opt/loboguara/bin/chromedriver'
    GOOGLE_CHROME_PATH = '/opt/loboguara/bin/google-chrome'
    FFUF_PATH = '/opt/loboguara/bin/ffuf'
    SUBFINDER_PATH = '/opt/loboguara/bin/subfinder'

    LOG_LEVEL = 'ERROR'
    LOG_FILE = '/opt/loboguara/logs/loboguara.log'
```

4. Make the installation script executable and run it:

```bash
sudo chmod +x ./install.sh
sudo ./install.sh
```

5. Start the service after installation:

```bash
sudo -u loboguara /opt/loboguara/start.sh
```

Access the URL below to register the Lobo Guará Super Admin

```bash
http://your_address:7405/admin
```

![Super admin creation](images/superadmin.png)

## Online Platform

Access the Lobo Guará platform online: [https://loboguara.olivsec.com.br/](https://loboguara.olivsec.com.br/)

## License

This project is licensed under the [GNU Affero General Public License (AGPL-3.0)](https://www.gnu.org/licenses/agpl-3.0.html). This means that you can use, modify, and distribute the code freely, but any modification used in a public application must have its source code made available.
