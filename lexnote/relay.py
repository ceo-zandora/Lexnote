import asyncio
import logging
import email
import ssl
import smtplib
from email import policy
from aiosmtpd.smtp import SMTP
from aiosmtpd.controller import Controller
from django.utils import timezone
from asgiref.sync import sync_to_async

import os
import django
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from lexnote.models import Tenant, TransactionLog, TransactionEvent
from lexnote.engine import SignatureEngine

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
        
        # --- LOOP PROTECTION CHECK ---
        if msg.get('X-Lexnote-Processed') == 'true':
            logger.info(f"Loop Detected: Skipping message {msg.get('Message-ID')} already processed by Lexnote.")
            # We must still relay it back to M365 to break the loop, but WITHOUT processing
            return await self.bypass_loop(msg, mail_from)

        # 2. Resolve Tenant
        cross_tenant_id = msg.get('X-MS-Exchange-CrossTenant-Id')
        tenant = await self.resolve_tenant(mail_from, cross_tenant_id)
        
        if not tenant:
            return '550 Security Failure: Tenant unauthorized'

        # 3. Initialize Transaction
        tx = await self.create_transaction(tenant, mail_from, rcpt_tos, msg.get('Message-ID'), cross_tenant_id)
        await self.log_event(tx, 'received', f"Secure Inbound from {peer[0]}")

        try:
            # 4. Process Signature
            engine = SignatureEngine(tenant, tx)
            modified_msg, result_status = await engine.process_message(msg)

            # 5. Inject Forensic Headers before Return
            # We add these regardless of SIGNED or BYPASS status to prevent re-entry
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
            logger.exception("SMTP Processing Error")
            tx.status = 'failed'
            tx.error_message = str(e)
            await sync_to_async(tx.save)()
            return '451 Local processing error'

    async def bypass_loop(self, msg, mail_from):
        """Relays a message that has already been processed to prevent infinite loops."""
        sender_domain = mail_from.split('@')[-1].lower()
        mx_endpoint = f"{sender_domain.replace('.', '-')}.mail.protection.outlook.com"
        
        # We don't create a full TransactionLog here to save DB space on loops, 
        # just relay it back as is.
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
        """Relays the message back to M365 using TLS."""
        def send():
            try:
                with smtplib.SMTP(mx_endpoint, 25, timeout=30) as smtp:
                    smtp.starttls(context=self.outbound_ssl_context)
                    smtp.send_message(msg)
                return True
            except Exception as e:
                logger.error(f"Relay Error: {e}")
                return False

        return await asyncio.to_thread(send)

def run_smtp_server():
    handler = LexnoteSMTPHandler()
    inbound_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    inbound_ssl_context.load_cert_chain(handler.cert_chain, handler.priv_key)

    controller = Controller(handler, hostname='0.0.0.0', port=25, ssl_context=inbound_ssl_context)
    print(f"Lexnote Secure Relay active on port 25 (Loop Protection Enabled)")
    controller.start()
    
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()