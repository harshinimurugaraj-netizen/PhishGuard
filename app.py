
from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)


def check_url(url):
    score = 0
    reasons = []

    if not url or len(url) > 2048:
        return {
            "status": "Invalid URL",
            "score": 0,
            "reasons": ["Please enter a valid URL."]
        }

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host or "." not in host:
        return {
            "status": "Invalid URL",
            "score": 0,
            "reasons": ["The URL format is invalid."]
        }

    if parsed.scheme != "https":
        score += 1
        reasons.append("Website does not use HTTPS.")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("URL contains an unusual @ symbol.")

    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append("URL uses an IP address instead of a domain.")
    except ValueError:
        pass

    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("Domain contains encoded characters.")

    keywords = [
        "login", "verify", "password", "bank",
        "account", "secure", "update", "signin"
    ]

    found = [word for word in keywords if word in url.lower()]

    if found:
        score += 1
        reasons.append("Contains suspicious keywords: " + ", ".join(found))

    if host.count("-") >= 3:
        score += 1
        reasons.append("Domain contains many hyphens.")

    if len(host.split(".")) > 4:
        score += 1
        reasons.append("Domain contains many subdomains.")

    if score >= 2:
        status = "Suspicious"
    else:
        status = "No obvious threats detected"

    if not reasons:
        reasons.append("No suspicious patterns detected.")

    return {
        "status": status,
        "score": score,
        "reasons": reasons
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        result = check_url(submitted_url)

    return render_template(
        "index.html",
        result=result,
        submitted_url=submitted_url
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000,debug=False)
    
