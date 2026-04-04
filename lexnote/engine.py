import email
from bs4 import BeautifulSoup

def populate_signature(html_template, user):
    """Replaces {{tags}} with DirectoryUser data"""
    tags = {
        "{{first_name}}": user.first_name,
        "{{last_name}}": user.last_name,
        "{{email}}": user.email,
        "{{designation}}": user.designation,
        "{{department}}": user.department,
        "{{company}}": user.company_name,
        "{{phone}}": user.phone,
        "{{office_phone}}": user.office_phone,
    }
    
    populated_html = html_template
    for tag, value in tags.items():
        populated_html = populated_html.replace(tag, str(value or ""))
    
    return populated_html

def inject_signature_to_mime(raw_email_bytes, signature_html):
    msg = email.message_from_bytes(raw_email_bytes)
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    payload = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                    # Inject before </body> or just append
                    if "</body>" in payload.lower():
                        new_payload = payload.replace("</body>", f"<br>{signature_html}</body>")
                    else:
                        new_payload = payload + f"<br>{signature_html}"
                    
                    part.set_payload(new_payload, charset='utf-8')
                except Exception:
                    continue
    
    return msg.as_bytes()