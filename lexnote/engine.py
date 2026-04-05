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
        await sync_to_async(TransactionEvent.objects.create)(
            transaction=self.tx,
            event_type=event_type,
            level=level,
            message=message,
            metadata=meta or {}
        )

    def get_matching_policy(self, user):
        """
        Evaluates the ABAC (Attribute-Based Access Control) logic.
        Exclusions always take precedence over Inclusions.
        """
        policies = Policy.objects.filter(
            tenant=self.tenant, 
            is_active=True
        ).order_by('-priority').prefetch_related('target_groups', 'exclude_groups')

        for policy in policies:
            # --- PHASE 1: EXCLUSIONS ---
            if user in policy.exclude_users.all():
                continue
            
            # Check if user is in an excluded group
            if policy.exclude_groups.filter(members=user).exists():
                continue

            # Check excluded departments (comma-separated)
            if policy.exclude_departments and user.department:
                excluded_depts = [d.strip().lower() for d in policy.exclude_departments.split(',')]
                if user.department.lower() in excluded_depts:
                    continue

            # --- PHASE 2: INCLUSIONS ---
            is_targeted = False

            # A) Direct Targeting
            if user in policy.target_users.all():
                is_targeted = True
            
            if not is_targeted and policy.target_groups.filter(members=user).exists():
                is_targeted = True

            # B) Attribute-Based Targeting (Dept, City, State, Company)
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

    def render_signature(self, template, user):
        """
        Replaces placeholders like {{display_name}} with actual user data.
        """
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
        """
        Main Entry Point for the SMTP Handler.
        Returns (modified_mime_msg, status)
        """
        sender_email = mime_msg.get('From')
        # Clean sender email from "Name <email@domain.com>" format
        clean_sender = re.findall(r'[\w\.-]+@[\w\.-]+', sender_email)[0].lower()
        
        self.tx.sender = clean_sender
        await sync_to_async(self.tx.save)()

        # 1. Identify User
        user = await sync_to_async(LexUser.objects.filter(
            tenant=self.tenant, 
            email__iexact=clean_sender, 
            is_active=True
        ).first)()

        if not user:
            await self.log_event('directory_user_missing', f"No active user found for {clean_sender}")
            self.tx.status = 'bypassed'
            return mime_msg, 'BYPASS'

        self.tx.directory_user = user
        await self.log_event('directory_user_matched', f"User matched: {user.display_name}")

        # 2. Match Policy
        policy = await sync_to_async(self.get_matching_policy)(user)
        if not policy:
            await self.log_event('policy_not_matched', "No matching policy found for user attributes")
            self.tx.status = 'bypassed'
            return mime_msg, 'BYPASS'

        self.tx.policy_applied = policy
        await self.log_event('policy_matched', f"Policy applied: {policy.name}")

        # 3. Determine Template (Initial vs Reply)
        is_reply = 'In-Reply-To' in mime_msg or 'References' in mime_msg
        template = policy.reply_signature if is_reply and policy.reply_signature else policy.initial_signature
        
        if not template:
            await self.log_event('processing_bypassed', "Policy matched but no template assigned")
            self.tx.status = 'bypassed'
            return mime_msg, 'BYPASS'

        self.tx.template_applied = template
        rendered_sig = self.render_signature(template, user)

        # 4. MIME Injection
        try:
            modified_msg = self.inject_html_signature(mime_msg, rendered_sig, is_reply)
            self.tx.status = 'signed'
            self.tx.processed_at = timezone.now()
            await self.log_event('processing_completed', "Signature successfully injected into MIME")
            return modified_msg, 'SIGNED'
        except Exception as e:
            await self.log_event('processing_failed', f"MIME injection error: {str(e)}", level='error')
            self.tx.status = 'failed'
            self.tx.error_message = str(e)
            return mime_msg, 'FAILED'

    def inject_html_signature(self, msg, signature_html, is_reply):
        """
        Handles the actual HTML insertion. 
        In production, we strictly target the HTML part of the multipart message.
        """
        if not msg.is_multipart():
            # For simplicity in this snippet, we assume multipart/alternative
            return msg

        for part in msg.walk():
            if part.get_content_type() == "text/html":
                original_html = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                soup = BeautifulSoup(original_html, 'html.parser')

                # Create signature container
                sig_soup = BeautifulSoup(f'<div class="lexnote-signature">{signature_html}</div>', 'html.parser')

                if is_reply:
                    # In replies, we try to insert BEFORE the first <blockquote> or 'MSExchange' thread separator
                    separator = soup.find(['blockquote', 'div'], id=re.compile(r'appendonsend|divRplyFwdMsg|Signature', re.I))
                    if separator:
                        separator.insert_before(sig_soup)
                    else:
                        # Fallback for replies: insert at the top of body
                        if soup.body:
                            soup.body.insert(0, sig_soup)
                else:
                    # Initial email: append to the end of the body
                    if soup.body:
                        soup.body.append(sig_soup)
                    else:
                        soup.append(sig_soup)

                part.set_payload(str(soup).encode('utf-8'))
                break
        
        return msg