import email
from email import policy
from email.utils import parseaddr
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from bs4 import BeautifulSoup
import re


@dataclass
class ParsedLink:
    href: str
    text: str


@dataclass
class ParsedImage:
    filename: str
    content_type: str
    content_id: Optional[str]
    data: bytes


@dataclass
class ParsedEmail:
    raw_headers: Dict[str, str]
    from_header: str
    sender_address: str
    sender_domain: str
    reply_to_header: str
    reply_to_address: str
    reply_to_domain: str
    return_path: str
    return_path_domain: str
    to_header: str
    subject: str
    date: str
    received_headers: List[str] = field(default_factory=list)
    authentication_results: str = ""
    received_spf: str = ""
    dkim_signature: str = ""
    body_plain: str = ""
    body_html: str = ""
    links: List[ParsedLink] = field(default_factory=list)
    images: List[ParsedImage] = field(default_factory=list)


def extract_domain(address: str) -> str:
    """Extract domain from an email address string."""
    if not address or "@" not in address:
        return ""
    _, addr = parseaddr(address)
    target = addr if addr else address
    target = target.strip().rstrip(">")
    if "@" not in target:
        return ""
    parts = target.split("@")
    return parts[-1].strip().lower()


def parse_eml(source: Union[str, Path, bytes]) -> ParsedEmail:
    """
    Parses a .eml file path or raw bytes into a ParsedEmail data object.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    elif isinstance(source, bytes):
        msg = email.message_from_bytes(source, policy=policy.default)
    else:
        raise ValueError("Unsupported source format for parse_eml. Expected path or bytes.")

    # Header extraction
    headers = {}
    for k, v in msg.items():
        headers[k] = str(v)

    from_header = str(msg.get("From", ""))
    reply_to_header = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    to_header = str(msg.get("To", ""))
    subject = str(msg.get("Subject", ""))
    date_header = str(msg.get("Date", ""))

    auth_results = str(msg.get("Authentication-Results", ""))
    received_spf = str(msg.get("Received-SPF", ""))
    dkim_sig = str(msg.get("DKIM-Signature", ""))

    _, sender_addr = parseaddr(from_header)
    sender_domain = extract_domain(sender_addr)

    _, reply_to_addr = parseaddr(reply_to_header)
    reply_to_domain = extract_domain(reply_to_addr)

    _, return_path_addr = parseaddr(return_path)
    return_path_domain = extract_domain(return_path_addr)

    received_headers = [str(r) for r in msg.get_all("Received", [])]

    body_plain_parts = []
    body_html_parts = []
    extracted_images: List[ParsedImage] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            content_id = part.get("Content-ID", None)
            if content_id:
                content_id = content_id.strip("<>")

            if content_type.startswith("image/"):
                img_data = part.get_payload(decode=True)
                if img_data:
                    filename = part.get_filename() or f"image_{len(extracted_images)+1}.png"
                    extracted_images.append(ParsedImage(
                        filename=filename,
                        content_type=content_type,
                        content_id=content_id,
                        data=img_data
                    ))
            elif content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_plain_parts.append(payload.decode(charset, errors="ignore"))
            elif content_type == "text/html" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_html_parts.append(payload.decode(charset, errors="ignore"))
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded_text = payload.decode(charset, errors="ignore")
            if content_type == "text/html":
                body_html_parts.append(decoded_text)
            else:
                body_plain_parts.append(decoded_text)

    body_plain = "\n".join(body_plain_parts)
    body_html = "\n".join(body_html_parts)

    # Link extraction from HTML
    extracted_links: List[ParsedLink] = []
    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            text = a_tag.get_text(strip=True)
            if href:
                extracted_links.append(ParsedLink(href=href, text=text))

    # Fallback link extraction from plain text if no HTML links
    if not extracted_links and body_plain:
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body_plain)
        for url in urls:
            extracted_links.append(ParsedLink(href=url, text=url))

    return ParsedEmail(
        raw_headers=headers,
        from_header=from_header,
        sender_address=sender_addr,
        sender_domain=sender_domain,
        reply_to_header=reply_to_header,
        reply_to_address=reply_to_addr,
        reply_to_domain=reply_to_domain,
        return_path=return_path_addr,
        return_path_domain=return_path_domain,
        to_header=to_header,
        subject=subject,
        date=date_header,
        received_headers=received_headers,
        authentication_results=auth_results,
        received_spf=received_spf,
        dkim_signature=dkim_sig,
        body_plain=body_plain,
        body_html=body_html,
        links=extracted_links,
        images=extracted_images,
    )
