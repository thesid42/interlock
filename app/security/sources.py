"""Bounded HTTPS collection; model output never selects a source or destination."""

import hashlib
import ipaddress
import re
import socket
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx


DEFAULT_HOSTS = ("genai.owasp.org", "docs.slack.dev", "docs.guild.ai", "docs.docker.com", "huggingface.co")


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


def validate_url(url, allowed_hosts):
    if not isinstance(url, str) or len(url) > 1500:
        raise ValueError("Source URL must be a bounded HTTPS URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid source URL") from None
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or port not in (None, 443) or parsed.fragment or parsed.query
            or host not in allowed_hosts or not host.isascii()):
        raise ValueError("Source must use an approved HTTPS host without credentials, query, or fragment")
    return url, host


def collect(url, allowed_hosts):
    url, host = validate_url(url, allowed_hosts)
    addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Source DNS must resolve only to public addresses")
    # Connect to the validated IP while preserving TLS hostname verification.
    pinned = httpx.URL(url).copy_with(host=sorted(addresses)[0])
    with httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", pinned, headers={"Host": host, "User-Agent": "Interlock/0.1", "Accept": "text/html,text/plain,application/json"},
                           extensions={"sni_hostname": host}) as response:
            response.raise_for_status()
            if 300 <= response.status_code < 400:
                raise ValueError("Source redirects are not followed; register the canonical approved URL")
            media = response.headers.get("content-type", "").split(";")[0].lower()
            if media not in {"text/html", "text/plain", "application/json", "application/xhtml+xml"}:
                raise ValueError("Source must be HTML, text, or JSON")
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 512_000:
                    raise ValueError("Source response exceeds the collection limit")
                chunks.append(chunk)
            raw = b"".join(chunks)
    text = raw.decode("utf-8", errors="replace")
    if media in {"text/html", "application/xhtml+xml"}:
        parser = TextExtractor()
        parser.feed(text)
        text = "\n".join(parser.parts)
    text = text[:8000]
    if not text.strip():
        raise ValueError("Source has no usable text")
    return {"url": url, "content": text, "content_hash": hashlib.sha256(text.encode()).hexdigest(),
            "response_hash": hashlib.sha256(raw).hexdigest(), "truncated": len(text) == 8000}


def suspicious_instruction(content, allowed_hosts):
    lower = content.lower()
    redirect = re.search(r"(?:ignore|override|disregard)\s+(?:all\s+)?(?:previous|prior|system|safety|security)\s+(?:instructions|rules|policy)", lower)
    outbound = re.search(r"\b(?:exfiltrate|upload|send|export)\b", lower)
    destinations = re.findall(r"https?://[^\s<>\"']+", content)
    foreign = [url for url in destinations if (urlsplit(url).hostname or "") not in allowed_hosts]
    if redirect and outbound and foreign:
        return "S1", "Source matches a policy-override plus external-transfer instruction signature"
    return None
