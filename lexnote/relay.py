import os
import sys
import django
import asyncio
import logging
import email
import ssl
import smtplib
import time
from pathlib import Path
from email import policy
from aiosmtpd.controller import Controller
from django.utils import timezone
from asgiref.sync import sync_to_async

# --- Django Bootstrap ---
# This ensures the script can find 'core' and 'lexnote' apps
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

# Local Imports after Django Setup
from lexnote.models import Tenant, TransactionLog, TransactionEvent
from lexnote.engine import SignatureEngine

# --- Logging Configuration ---
# Configured to show in journalctl and the forensic_audit.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('lexnote.smtp')

class LexnoteSMTPHandler:
    def __init__(self):
        self.cert_chain = '/etc/letsencrypt/live/lexnote.org/fullchain.pem'
        self.priv_key = '/etc/letsencrypt/live/lexnote.org/privkey.pem'
        self.outbound_ssl_context = ssl.create_default_context()

    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        raw_data = envelope.content
        
        # 1. Parse MIME
        msg = email.message_from_bytes(raw_data, policy=policy.default)
        
        # --- LOOP PROTECTION ---
        if msg.get('X-Lexnote-Processed') == 'true':
            logger.info(f"Loop Detected: Skipping message {msg.get('Message-ID')}")
            return await self.bypass_loop(msg, mail_from)

        # 2. Resolve Tenant
        cross_tenant_id = msg.get('X-MS-Exchange-CrossTenant-Id')
        tenant = await self.resolve_tenant(mail_from, cross_tenant_id)
        
        if not tenant:
            logger.error(f"Unauthorized access attempt from {mail_from} (Tenant ID: {cross_tenant_id})")
            return '550 Security Failure: Tenant unauthorized'

        # 3. Initialize Transaction
        tx = await self.create_transaction(tenant, mail_from, rcpt_tos, msg.get('Message-ID'), cross_tenant_id)
        await self.log_event(tx, 'received', f"Secure Inbound from {peer[0]}")

        try:
            # 4. Process Signature
            engine = SignatureEngine(tenant, tx)
            modified_msg, result_status = await engine.process_message(msg)

            # 5. Inject Forensic Headers
            modified_msg['X-Lexnote-Processed'] = 'true'
            modified_msg['X-Lexnote-TRN'] = str(tx.trn)

            # 6. Secure Return Path
            if result_status in ['SIGNED', 'BYPASS']:
                sender_domain = mail_from.split('@')[-1].lower()
                mx_endpoint = f"{sender_domain.replace('.', '-')}.mail.protection.outlook.com"
                
                relay_success = await self.relay_to_m365(modified_msg, mx_endpoint, tx)
                
                if relay_success:
                    tx.status = 'returned'
                    await self.log_event(tx, 'returned_to_m365', f"Relayed via TLS to {mx_endpoint}")
                else:
                    tx.status = 'failed'
                    await self.log_event(tx, 'processing_failed', "Outbound TLS Relay Failed", level='error')
            
            await sync_to_async(tx.save)()
            return '250 OK'

        except Exception as e:
            logger.exception("Internal SMTP Processing Error")
            tx.status = 'failed'
            tx.error_message = str(e)
            await sync_to_async(tx.save)()
            return '451 Local processing error'

    async def bypass_loop(self, msg, mail_from):
        sender_domain = mail_from.split('@')[-1].lower()
        mx_endpoint = f"{sender_domain.replace('.', '-')}.mail.protection.outlook.com"
        success = await self.relay_to_m365(msg, mx_endpoint, None)
        return '250 OK' if success else '451 Relay Error'

    async def resolve_tenant(self, mail_from, cross_tenant_id):
        if cross_tenant_id:
            tenant = await sync_to_async(Tenant.objects.filter(tenant_id=cross_tenant_id, is_active=True).first)()
            if tenant: return tenant
        domain = mail_from.split('@')[-1].lower()
        return await sync_to_async(Tenant.objects.filter(domain__iexact=domain, is_active=True).first)()

    @sync_to_async
    def create_transaction(self, tenant, sender, recipients, msg_id, cross_id):
        return TransactionLog.objects.create(
            tenant=tenant,
            trigger_type='MAIL',
            sender=sender,
            recipients={'to': recipients},
            internet_message_id=msg_id,
            cross_tenant_id=cross_id,
            status='processing'
        )

    async def log_event(self, tx, event_type, message, level='info'):
        if not tx: return
        await sync_to_async(TransactionEvent.objects.create)(
            transaction=tx, event_type=event_type, level=level, message=message
        )

    async def relay_to_m365(self, msg, mx_endpoint, tx):
        def send():
            try:
                with smtplib.SMTP(mx_endpoint, 25, timeout=30) as smtp:
                    smtp.starttls(context=self.outbound_ssl_context)
                    smtp.send_message(msg)
                return True
            except Exception as e:
                logger.error(f"Outbound Relay Error to {mx_endpoint}: {e}")
                return False
        return await asyncio.to_thread(send)

def run_smtp_server():
    handler = LexnoteSMTPHandler()
    
    # Inbound SSL Configuration
    inbound_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    inbound_ssl_context.load_cert_chain(handler.cert_chain, handler.priv_key)

    # Controller setup using modern TLS context and no mandatory STARTTLS
    controller = Controller(
        handler, 
        hostname='0.0.0.0', 
        port=25, 
        tls_context=inbound_ssl_context,
        require_starttls=False
    )
    
    controller.start()
    logger.info("Lexnote Secure Relay started on port 25...")
    
    try:
        # Keep-alive loop
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Relay received shutdown signal...")
    finally:
        controller.stop()
        logger.info("Relay stopped.")

if __name__ == "__main__":
    run_smtp_server()