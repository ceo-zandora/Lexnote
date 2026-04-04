import asyncio
import os
import django
import email
import smtplib
import ssl
import dns.resolver
from aiosmtpd.controller import Controller

# 1. Initialize Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from lexnote.models import Tenant, DirectoryUser, TransactionLog, SignaturePolicy
from lexnote.engine import populate_signature, inject_signature_to_mime

class LexnoteProductionHandler:
    def __init__(self):
        # Unified Wildcard Paths
        self.cert_chain = '/etc/letsencrypt/live/lexnote.org/fullchain.pem'
        self.priv_key = '/etc/letsencrypt/live/lexnote.org/privkey.pem'
        
        # Create SSL context for the Outbound leg (Lexnote -> M365)
        self.ssl_context = ssl.create_default_context()

    def get_mx_record(self, domain):
        """Finds the M365 Inbound Endpoint for the recipient domain."""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            # Get the record with the lowest preference number
            best_mx = sorted(answers, key=lambda r: r.preference)[0].exchange.to_text()
            return best_mx.rstrip('.')
        except Exception as e:
            print(f"DNS MX Lookup failed for {domain}: {e}")
            return None

    async def handle_DATA(self, server, session, envelope):
        raw_data = envelope.content
        sender = envelope.mail_from
        recipients = envelope.rcpt_tos
        
        # Identify Tenant via Subdomain (e.g., ZANX.smtp.lexnote.org)
        target_hostname = getattr(session, 'host_name', 'UNKNOWN').lower()
        relay_token = target_hostname.split('.')[0].upper()

        # Parse email for headers
        msg = email.message_from_bytes(raw_data)
        message_id = msg.get('Message-ID', 'N/A')

        # 2. Identify Tenant & Log Entry
        tenant = Tenant.objects.filter(relay_token=relay_token).first()
        
        log = TransactionLog.objects.create(
            tenant=tenant if tenant else Tenant.objects.first(),
            sender=sender,
            recipient=", ".join(recipients),
            message_id=message_id,
            status='failed'
        )

        try:
            # 3. Validation & Loop Prevention
            if not tenant:
                log.processing_notes = f"Unknown Relay Token: {relay_token}"
                log.save()
                self.relay_to_m365(raw_data, sender, recipients)
                return '250 OK'

            if msg.get('X-Lexnote-Processed') == 'true':
                log.status = 'bypassed'
                log.processing_notes = "Loop Detection: Skipping."
                log.save()
                self.relay_to_m365(raw_data, sender, recipients)
                return '250 OK'

            # 4. Signature Logic
            user = DirectoryUser.objects.filter(email=sender, tenant=tenant, is_active=True).first()
            if not user:
                log.status = 'bypassed'
                log.processing_notes = "User not found in Directory."
                log.save()
                self.relay_to_m365(raw_data, sender, recipients)
                return '250 OK'

            # Determine if Initial or Reply
            is_reply = 'In-Reply-To' in msg or 'References' in msg
            policy = SignaturePolicy.objects.filter(tenant=tenant).first()
            
            if not policy:
                raise ValueError("No Signature Policy found for tenant.")

            template = policy.reply_template if is_reply and policy.reply_template else policy.initial_template
            
            # 5. Inject Signature
            populated_sig = populate_signature(template.html_content, user)
            processed_bytes = inject_signature_to_mime(raw_data, populated_sig)

            # 6. Final Header Injection (CISO Forensics)
            final_msg = email.message_from_bytes(processed_bytes)
            del final_msg['X-Lexnote-Processed'] # Clear old ones
            del final_msg['X-Lexnote-TXN']
            
            final_msg['X-Lexnote-Processed'] = 'true'
            final_msg['X-Lexnote-TXN'] = log.trn
            
            # 7. Deliver back to M365
            self.relay_to_m365(final_msg.as_bytes(), sender, recipients)

            log.status = 'signed'
            log.is_reply = is_reply
            log.save()
            print(f"[{log.trn}] SUCCESS: Processed mail for {sender}")
            return '250 OK'

        except Exception as e:
            log.processing_notes = f"Relay Error: {str(e)}"
            log.save()
            print(f"[{log.trn}] FAIL-SAFE: Relaying original due to error: {e}")
            self.relay_to_m365(raw_data, sender, recipients)
            return '250 OK'

    def relay_to_m365(self, data, sender, recipients):
        """Delivers mail to the destination MX via Port 25 with STARTTLS."""
        domain = sender.split('@')[-1]
        mx_endpoint = self.get_mx_record(domain)
        
        if not mx_endpoint:
            print(f"Critical: No destination found for {domain}")
            return

        try:
            # Connect to M365 on Port 25
            with smtplib.SMTP(mx_endpoint, 25, timeout=20) as server:
                server.ehlo('smtp.lexnote.org')
                if server.has_extn('STARTTLS'):
                    server.starttls(context=self.ssl_context)
                    server.ehlo()
                server.sendmail(sender, recipients, data)
        except Exception as e:
            print(f"SMTP Outbound Error to {mx_endpoint}: {e}")

if __name__ == '__main__':
    # Initialize the Handler
    handler = LexnoteProductionHandler()
    
    # Define SSL for Inbound connection (M365 -> Lexnote)
    # This allows M365 to verify our identity via the certs you just made
    inbound_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    inbound_ssl_context.load_cert_chain(handler.cert_chain, handler.priv_key)

    # Start the Controller on Port 25 (Requires sudo/root)
    controller = Controller(
        handler, 
        hostname='0.0.0.0', 
        port=25, 
        ssl_context=inbound_ssl_context
    )
    
    print("==================================================")
    print("   LEXNOTE SECURE RELAY ACTIVE ON PORT 25         ")
    print("   SSL: ENABLED (*.smtp.lexnote.org)              ")
    print("==================================================")
    
    controller.start()
    
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()