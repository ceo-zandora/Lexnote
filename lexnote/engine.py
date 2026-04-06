import re
import logging
from bs4 import BeautifulSoup
from django.utils import timezone
from django.db.models import Q
from .models import Policy, LexUser, TransactionLog, TransactionEvent
from asgiref.sync import sync_to_async

logger = logging.getLogger('lexnote.engine')

class SignatureEngine:
    def __init__(self, tenant, transaction: TransactionLog):
        self.tenant = tenant
        self.tx = transaction

    async def log_event(self, event_type, message, level='info', meta=None):
        """Helper to link engine steps to the forensic trail."""
        await sync_to_async(TransactionEvent.objects.create, thread_sensitive=True)(
            transaction=self.tx,
            event_type=event_type,
            level=level,
            message=message,
            metadata=meta or {}
        )

    def _get_matching_policy_sync(self, user):
        """
        Internal synchronous helper to handle complex ORM lookups.
        """
        policies = Policy.objects.filter(
            tenant=self.tenant, 
            is_active=True
        ).order_by('-priority')

        for policy in policies:
            # --- PHASE 1: EXCLUSIONS ---
            if policy.exclude_users.filter(pk=user.pk).exists():
                continue
            
            if policy.exclude_groups.filter(members=user).exists():
                continue

            if policy.exclude_departments and user.department:
                excluded_depts = [d.strip().lower() for d in policy.exclude_departments.split(',')]
                if user.department.lower() in excluded_depts:
                    continue

            # --- PHASE 2: INCLUSIONS ---
            is_targeted = False

            if policy.target_users.filter(pk=user.pk).exists():
                is_targeted = True
            
            if not is_targeted and policy.target_groups.filter(members=user).exists():
                is_targeted = True

            if not is_targeted:
                match_map = {
                    'target_departments': user.department,
                    'target_cities': user.city,
                    'target_states': user.state,
                    'target_companies': user.company_name,
                    'target_office_locations': user.city,
                }
                
                for attr_field, user_value in match_map.items():
                    policy_attr_value = getattr(policy, attr_field)
                    if policy_attr_value and user_value:
                        allowed_values = [v.strip().lower() for v in policy_attr_value.split(',')]
                        if user_value.lower() in allowed_values:
                            is_targeted = True
                            break

            if is_targeted:
                return policy
        return None

    @sync_to_async
    def _get_templates_sync(self, policy):
        """Safely fetch foreign key relations."""
        return policy.initial_signature, policy.reply_signature

    def render_signature(self, template, user):
        """Replaces placeholders with actual user data."""
        content = template.html_content
        placeholders = {
            '{{display_name}}': user.display_name or "",
            '{{first_name}}': user.first_name or "",
            '{{last_name}}': user.last_name or "",
            '{{employee_id}}': user.employee_id or "",
            '{{state}}': user.state or "",
            '{{office_location}}': user.office_location or "",
            '{{designation}}': user.designation or "",
            '{{department}}': user.department or "",
            '{{mobile_phone}}': user.mobile_phone or "",
            '{{office_phone}}': user.office_phone or "",
            '{{fax_number}}': user.fax_number or "",
            '{{email}}': user.email or "",
            '{{company_name}}': user.company_name or "",
            '{{city}}': user.city or "",
        }
        
        for key, val in placeholders.items():
            content = content.replace(key, str(val))
        return content

    async def process_message(self, mime_msg):
        """Main Entry Point for the SMTP Handler."""
        sender_email = mime_msg.get('From', '')
        match = re.search(r'[\w\.-]+@[\w\.-]+', sender_email)
        if not match:
            return mime_msg, 'BYPASS'
        
        clean_sender = match.group(0).lower()
        self.tx.sender = clean_sender
        await sync_to_async(self.tx.save, thread_sensitive=True)()

        # 1. Identify User
        user = await sync_to_async(
            lambda: LexUser.objects.filter(
                tenant=self.tenant, 
                email__iexact=clean_sender, 
                is_active=True
            ).first(), 
            thread_sensitive=True
        )()

        if not user:
            await self.log_event('directory_user_missing', f"No active user found for {clean_sender}")
            self.tx.status = 'bypassed'
            await sync_to_async(self.tx.save)()
            return mime_msg, 'BYPASS'

        self.tx.directory_user = user
        await self.log_event('directory_user_matched', f"User matched: {user.display_name}")

        # 2. Match Policy (Wrapped in sync_to_async)
        policy = await sync_to_async(self._get_matching_policy_sync, thread_sensitive=True)(user)
        if not policy:
            await self.log_event('policy_not_matched', "No matching policy found")
            self.tx.status = 'bypassed'
            await sync_to_async(self.tx.save)()
            return mime_msg, 'BYPASS'

        self.tx.policy_applied = policy
        await self.log_event('policy_matched', f"Policy applied: {policy.name}")

        # 3. Determine Template (Fetch FKs safely)
        is_reply = 'In-Reply-To' in mime_msg or 'References' in mime_msg
        initial_sig, reply_sig = await self._get_templates_sync(policy)
        
        template = reply_sig if is_reply and reply_sig else initial_sig
        
        if not template:
            await self.log_event('processing_bypassed', "Policy matched but no template assigned")
            self.tx.status = 'bypassed'
            await sync_to_async(self.tx.save)()
            return mime_msg, 'BYPASS'

        self.tx.template_applied = template
        rendered_sig = self.render_signature(template, user)

        # 4. MIME Injection
        try:
            modified_msg = self.inject_html_signature(mime_msg, rendered_sig, is_reply)
            self.tx.status = 'signed'
            self.tx.processed_at = timezone.now()
            await self.log_event('processing_completed', "Signature successfully injected")
            await sync_to_async(self.tx.save)()
            return modified_msg, 'SIGNED'
        except Exception as e:
            await self.log_event('processing_failed', f"MIME injection error: {str(e)}", level='error')
            self.tx.status = 'failed'
            self.tx.error_message = str(e)
            await sync_to_async(self.tx.save)()
            return mime_msg, 'FAILED'

    def inject_html_signature(self, msg, signature_html, is_reply):
        if not msg.is_multipart():
            return msg

        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    original_html = payload.decode(charset, errors='replace')
                    
                    soup = BeautifulSoup(original_html, 'html.parser')
                    sig_container = f'<div class="lexnote-signature" style="margin-top:20px;">{signature_html}</div>'
                    sig_soup = BeautifulSoup(sig_container, 'html.parser')

                    if is_reply:
                        # Target common thread separators
                        separator = soup.find(['blockquote', 'div', 'hr'], id=re.compile(r'appendonsend|divRplyFwdMsg|Signature|x_divRplyFwdMsg', re.I))
                        if separator:
                            separator.insert_before(sig_soup)
                        elif soup.body:
                            soup.body.insert(0, sig_soup)
                    else:
                        if soup.body:
                            soup.body.append(sig_soup)
                        else:
                            soup.append(sig_soup)

                    part.set_payload(str(soup).encode(charset))
                except Exception as e:
                    logger.error(f"Error injecting signature: {e}")
                break
        return msg