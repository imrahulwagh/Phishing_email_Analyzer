import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from pathlib import Path

msg = MIMEMultipart('related')
msg['From'] = 'PayPal Security <security-update@paypa1-verify.com>'
msg['To'] = 'user@victim.com'
msg['Reply-To'] = 'hacker-collect@evil-attacker.net'
msg['Return-Path'] = 'bounce@different-domain.org'
msg['Subject'] = 'URGENT: Your PayPal Account Has Been Suspended'
msg['Date'] = 'Mon, 07 Sep 2026 11:30:00 +0000'
msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'
msg['Received-SPF'] = 'fail (google.com: domain of paypa1-verify.com does not designate permitted sender)'

html = """<!DOCTYPE html>
<html>
<body>
    <img src="cid:paypal_logo" alt="PayPal Logo" width="200" height="80" />
    <h2 style="color:red;">ACCOUNT SUSPENDED IMMEDIATELY</h2>
    <p>Dear Customer,</p>
    <p>Unauthorized login attempts were detected on your account. <b>Immediate action required</b> within 24 hours to prevent permanent account termination.</p>
    <p>Please click below to verify your account credentials immediately:</p>
    <p><a href="http://evil-phish.net/login-harvest">https://www.paypal.com/cgi-bin/webscr-verify</a></p>
    <p>Thank you,<br>PayPal Security Department</p>
</body>
</html>"""

msg.attach(MIMEText(html, 'html'))

logo_path = Path(r'C:\Users\Rahul Wagh\.gemini\antigravity\scratch\phishing_email_analyzer\image_analysis\reference_logos\paypal.png')
if logo_path.exists():
    with open(logo_path, 'rb') as f:
        img_data = f.read()
    img = MIMEImage(img_data)
    img.add_header('Content-ID', '<paypal_logo>')
    img.add_header('Content-Disposition', 'inline', filename='paypal_logo.png')
    msg.attach(img)

out_path = Path(r'C:\Users\Rahul Wagh\.gemini\antigravity\scratch\phishing_email_analyzer\tests\fixtures\phishing.eml')
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, 'wb') as f:
    f.write(msg.as_bytes())

print("Phishing email fixture created successfully!")
