import asyncio
import os
import django
import email
import smtplib
from aiosmtpd.controller import Controller
from email.utils import formataddr

# 1. Initialize Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from lexnote.models import Tenant, DirectoryUser, TransactionLog, SignaturePolicy
from lexnote.engine import populate_signature, inject_signature_to_mime

class LexnoteRelayHandler:
    def __init__(self):
        # In production, this will be dynamically determined by the recipient's MX
        # For testing, we use a local sink or a static M365 endpoint
        self.default_outbound_host = "127.0.0.1" 
        self.default_outbound_port = 1026 # Standard is 25 for production

    async def handle_DATA(self, server, session, envelope):
        """
        Main entry point for incoming mail from M365 Outbound Connector.
        """
        data = envelope.content
        sender = envelope.mail_from
        recipients = envelope.rcpt_tos
        
        # Identify which subdomain was targeted (e.g., ZANX123.smtp.lexnote.org)
        # aiosmtpd stores the HELO/EHLO hostname in session.host_name
        target_hostname = getattr(session, 'host_name', '')
        relay_token = target_hostname.split('.')[0].upper()

        # Parse the original email to extract headers for tracking
        msg = email.message_from_bytes(data)
        message_id = msg.get('Message-ID', 'UNKNOWN')
        cross_tenant_id = msg.get('X-MS-Exchange-CrossTenant-Id')

        # 2. Identify Tenant via Token (Subdomain)
        tenant = Tenant.objects.filter(relay_token=relay_token).first()
        
        # If token lookup fails, try Header lookup as backup
        if not tenant and cross_tenant_id:
            tenant = Tenant.objects.filter(tenant_id=cross_tenant_id).first()

        # 3. Initialize Audit Log (CISO Audit Trail)
        log = TransactionLog.objects.create(
            tenant=tenant if tenant else Tenant.objects.first(), # Fallback for logging
            sender=sender,
            recipient=", ".join(recipients),
            message_id=message_id,
            cross_tenant_id=cross_tenant_id,
            status='failed'
        )

        try:
            # 4. Security Check: Validate Tenant
            if not tenant:
                log.processing_notes = f"Rejected: Invalid Relay Token ({relay_token})"
                log.save()
                # If we don't recognize the tenant, we relay original to avoid blocking mail
                self.relay_to_destination(data, sender, recipients)
                return '250 OK'

            # 5. Check for Loop Prevention Header
            if msg.get('X-Lexnote-Processed') == 'true':
                log.status = 'bypassed'
                log.processing_notes = "Loop Detection: Skipping already processed mail."
                log.save()
                self.relay_to_destination(data, sender, recipients)
                return '250 OK'

            # 6. Fetch User & Determine Context
            user = DirectoryUser.objects.filter(email=sender, tenant=tenant, is_active=True).first()
            if not user:
                log.status = 'bypassed'
                log.processing_notes = "User not in Lexnote Directory. Relaying clean."
                log.save()
                self.relay_to_destination(data, sender, recipients)
                return '250 OK'

            is_reply = 'In-Reply-To' in msg or 'References' in msg
            log.is_reply = is_reply

            # 7. Apply Signature Policy
            policy = SignaturePolicy.objects.filter(tenant=tenant).first()
            if not policy:
                raise ValueError("No Signature Policy defined for this tenant.")

            log.policy_applied = policy
            template = policy.reply_template if is_reply and policy.reply_template else policy.initial_template
            
            # 8. Transform Email (Injection)
            populated_sig_html = populate_signature(template.html_content, user)
            processed_bytes = inject_signature_to_mime(data, populated_sig_html)

            # 9. Inject Loop Prevention & Forensics Headers
            final_msg = email.message_from_bytes(processed_bytes)
            
            # Ensure we don't duplicate headers
            del final_msg['X-Lexnote-Processed']
            del final_msg['X-Lexnote-TXN']
            
            final_msg['X-Lexnote-Processed'] = 'true'
            final_msg['X-Lexnote-TXN'] = log.trn
            
            # 10. Deliver back to M365
            self.relay_to_destination(final_msg.as_bytes(), sender, recipients)

            log.status = 'signed'
            log.save()
            print(f"[{log.trn}] SUCCESS: {sender} -> Processed via {relay_token}")
            return '250 OK'

        except Exception as e:
            # CISO FAIL-SAFE: Never block the mail flow
            log.processing_notes = f"CRITICAL FAILURE: {str(e)}"
            log.save()
            print(f"[{log.trn}] ERROR: {str(e)}. Falling back to original mail.")
            self.relay_to_destination(data, sender, recipients)
            return '250 OK'

    def relay_to_destination(self, data, sender, recipients):
        """
        Standard SMTP client to push the mail to the next hop.
        In production, this targets the M365 Inbound Connector.
        """
        try:
            with smtplib.SMTP(self.default_outbound_host, self.default_outbound_port) as server:
                # server.starttls() # Enable in Production with SSL
                server.sendmail(sender, recipients, data)
        except Exception as e:
            print(f"CRITICAL RELAY ERROR: Could not deliver mail to next hop: {e}")

if __name__ == '__main__':
    # Initialize the Async SMTP Controller
    # Listening on Port 1025 (Dev) or 25 (Prod)
    handler = LexnoteRelayHandler()
    controller = Controller(handler, hostname='0.0.0.0', port=1025)
    
    print("==========================================")
    print("   LEXNOTE SECURE SMTP RELAY STARTING     ")
    print("   Endpoint: *.smtp.lexnote.org:1025      ")
    print("==========================================")
    
    controller.start()
    
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()