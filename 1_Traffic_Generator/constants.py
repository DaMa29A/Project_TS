HTTP_TARGET = "http://192.168.20.10"
HTTPS_TARGET = "https://192.168.20.10"

TOTAL_ACTIONS = 100

HTTPS_RATIO = 0.4 #0.0 NO HTTPS
CHROME_RATIO = 0.25

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

ACCEPT_LANGUAGES = [
    "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "it-IT,it;q=0.8",
]

EXISTING_PATHS = [
    "/mfolder/index.html",
    "/mfolder/about.html",
    "/mfolder/contact.html",
    "/mfolder/info.json",
    "/mfolder/robots.txt",
    "/mfolder/status.txt",
    "/mfolder/cat.jpg",
    "/mfolder/styles.css",
]

MISSING_PATHS = [
    "/mfolder/favicon.ico",
    "/mfolder/app.js",
    "/mfolder/style.css",
    "/mfolder/missing.jpg",
    "/mfolder/api/data.json",
    "/mfolder/old-page.html",
]

CHROME_PATHS = [
    "/mfolder/index.html",
    "/mfolder/about.html",
    "/mfolder/contact.html",
]