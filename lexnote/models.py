from django.db import models
import uuid

def generate_relay_token():
    return uuid.uuid4().hex[:12].upper()

def generate_trn():
    return f"TRN{uuid.uuid4().hex[:12].upper()}"

# --- TENANT LAYER ---
class Tenant(models.Model):
    # The X-MS-Exchange-CrossTenant-id from Microsoft
    tenant_id = models.UUIDField(unique=True, primary_key=True)
    organization_name = models.CharField(max_length=255)
    
    # Randomized string for the Smart Host: {relay_token}.lexnote.org
    relay_token = models.CharField(max_length=20, default=generate_relay_token, unique=True)
    
    # Credentials for Graph API Sync
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.organization_name

class TenantDomain(models.Model):
    tenant = models.ForeignKey(Tenant, related_name='domains', on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=255, unique=True) # e.g. zanx.com

    def __str__(self):
        return f"{self.tenant.name} - {self.domain_name}"

# --- SIGNATURE LAYER ---
class SignatureTemplate(models.Model):
    name = models.CharField(max_length=100)
    html_content = models.TextField() # The raw HTML with {{tags}}
    
    TYPE_CHOICES = [
        ('initial', 'Initial Email'),
        ('reply', 'Reply/Forward'),
        ('universal', 'Universal (Both)'),
    ]
    sig_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='universal')

class SignaturePolicy(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    priority = models.IntegerField(default=0) # 0 = Highest Priority
    
    # Conditional Logic (Filters)
    target_domain = models.ForeignKey(TenantDomain, on_delete=models.SET_NULL, null=True, blank=True)
    target_country = models.CharField(max_length=100, blank=True)
    target_department = models.CharField(max_length=100, blank=True)
    target_company = models.CharField(max_length=255, blank=True) # For multi-company tenants
    
    # Template Mapping
    initial_template = models.ForeignKey(SignatureTemplate, related_name='initial_sig', on_delete=models.CASCADE)
    reply_template = models.ForeignKey(SignatureTemplate, related_name='reply_sig', on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        ordering = ['priority']
        verbose_name_plural = "Signature Policies"

# --- DIRECTORY LAYER ---
class DirectoryUser(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    designation = models.CharField(max_length=255)
    department = models.CharField(max_length=100)
    company_name = models.CharField(max_length=255)
    country = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    office_phone = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)
    last_synced = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [models.Index(fields=['email', 'tenant'])]

# --- AUDIT LAYER ---
class TransactionLog(models.Model):
    # --- Identification ---
    # Human-readable TRN (e.g., TRN-A8B2C3D4E5F6)
    trn = models.CharField(
        max_length=50, 
        unique=True, 
        default=generate_trn,
        editable=False
    )
    # The unique ID from Microsoft for cross-referencing in Exchange Logs
    message_id = models.CharField(max_length=255, db_index=True, help_text="Original Message-ID header")
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    
    # --- Mail Metadata ---
    sender = models.EmailField(db_index=True)
    recipient = models.TextField(help_text="Comma-separated list of recipients")
    subject = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    # --- Processing Results ---
    STATUS_CHOICES = [
        ('signed', 'Signed'),      # Success: Signature injected
        ('bypassed', 'Bypassed'),  # Intentional: e.g., S/MIME, Internal, or Duplicate
        ('failed', 'Failed'),      # Error: Fallback triggered, sent without signature
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    
    # Logic Tracking
    is_reply = models.BooleanField(default=False, help_text="Detected via In-Reply-To header")
    policy_applied = models.ForeignKey(
        SignaturePolicy, 
        null=True, 
        blank=True, 
        on_delete=models.SET_NULL,
        help_text="The specific policy that matched the sender attributes"
    )

    # --- Technical Audit Trail ---
    # Stores the X-MS-Exchange-CrossTenant-id for verification
    cross_tenant_id = models.UUIDField(null=True, blank=True)
    
    # Detailed log for failed or bypassed reasons
    # e.g., "Bypassed: application/pkcs7-mime detected (S/MIME)"
    # e.g., "Failed: User mohammed@zanx.com not found in DirectoryUser sync"
    processing_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['trn', 'sender']),
            models.Index(fields=['timestamp', 'status']),
        ]

    def __str__(self):
        return f"{self.trn} | {self.sender} | {self.status.upper()}"