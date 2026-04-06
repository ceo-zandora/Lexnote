from django.db import models
import uuid

def generate_trn():
    """
    Human-readable Transaction Reference Number
    Example: TRN6F13A9C3D2B1
    """
    return f"TRN{uuid.uuid4().hex[:12].upper()}"

class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class Tenant(TimeStampedModel):
    name = models.CharField(max_length=255)
    tenant_id = models.CharField(max_length=255, unique=True, help_text="M365 Directory ID")
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    relay_domain = models.CharField(max_length=255, unique=True, help_text="e.g. x1y2.smtp.lexnote.org")
    is_active = models.BooleanField(default=True)
    last_sync = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.tenant_id})"

class Group(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="groups")
    external_id = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    mail_enabled = models.BooleanField(default=False)
    security_enabled = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True, db_index=True)

    def __str__(self):
        return f"{self.display_name} - ({self.tenant.tenant_id})"

class LexUser(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="users")
    external_id = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    upn = models.EmailField()
    display_name = models.CharField(max_length=255)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    employee_id = models.CharField(max_length=100, blank=True, null=True)
    designation = models.CharField(max_length=255, blank=True, null=True)
    department = models.CharField(max_length=255, blank=True, null=True)
    office_location = models.CharField(max_length=255, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    mobile_phone = models.CharField(max_length=50, blank=True, null=True)
    office_phone = models.CharField(max_length=50, blank=True, null=True)
    fax_number = models.CharField(max_length=50, blank=True, null=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    groups = models.ManyToManyField(Group, related_name="members")

    def __str__(self):
        return f"{self.email} ({self.tenant.tenant_id})"

class SignatureTemplate(TimeStampedModel):
    name = models.CharField(max_length=100)
    html_content = models.TextField(help_text="Use placeholders like {{display_name}}, {{designation}}")
    
    def __str__(self):
        return self.name

class Policy(TimeStampedModel):
    name = models.CharField(max_length=100)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    priority = models.IntegerField(
        default=0, 
        help_text="Higher priority policies are evaluated first."
    )
    is_active = models.BooleanField(default=True, db_index=True)

    # --- INCLUSION CRITERIA (Targeting) ---
    target_users = models.ManyToManyField(
        LexUser, blank=True, related_name="targeted_by_policies"
    )
    target_groups = models.ManyToManyField(
        Group, blank=True, related_name="targeted_by_policies"
    )
    
    # Attribute-Based Targeting (Comma-separated or exact match)
    target_departments = models.TextField(
        blank=True, help_text="Comma-separated list of departments."
    )
    target_cities = models.TextField(
        blank=True, help_text="Comma-separated list of cities."
    )
    target_states = models.TextField(blank=True)
    target_companies = models.TextField(blank=True)
    target_office_locations = models.TextField(
        blank=True, help_text="Matches against the 'city' or 'office_location' field."
    )

    # --- EXCLUSION CRITERIA (The 'Except' Rule) ---
    exclude_users = models.ManyToManyField(
        LexUser, blank=True, related_name="excluded_from_policies"
    )
    exclude_groups = models.ManyToManyField(
        Group, blank=True, related_name="excluded_from_policies"
    )
    exclude_departments = models.TextField(blank=True)

    # --- SIGNATURE ASSIGNMENT ---
    initial_signature = models.ForeignKey(
        SignatureTemplate, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name="initial_policy"
    )
    reply_signature = models.ForeignKey(
        SignatureTemplate, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name="reply_policy"
    )

    class Meta:
        verbose_name_plural = "Policies"
        ordering = ['-priority']
        indexes = [
            models.Index(fields=['tenant', 'is_active', 'priority']),
        ]

    def __str__(self):
        return f"P{self.priority}: {self.name} ({self.tenant.name})"

class TransactionLog(TimeStampedModel):
    STATUS_CHOICES = [
        ("received", "Received"),
        ("processing", "Processing"),
        ("signed", "Signed"),
        ("bypassed", "Bypassed"),
        ("failed", "Failed"),
        ("returned", "Returned"),
        ("sync_success", "Sync Success"),
        ("sync_fail", "Sync Failed"),
    ]

    tenant = models.ForeignKey('Tenant', on_delete=models.CASCADE, related_name="transactions")
    trn = models.CharField(max_length=50, unique=True, default=generate_trn, db_index=True)
    
    # Identify what triggered this (Email or Sync)
    trigger_type = models.CharField(max_length=10, choices=[('MAIL', 'Mail Traffic'), ('SYNC', 'Directory Sync')], default='MAIL')
    
    # Core Identity
    sender = models.EmailField(db_index=True, blank=True, null=True)
    recipients = models.JSONField(default=dict) 
    cross_tenant_id = models.CharField(max_length=255, null=True, blank=True)
    internet_message_id = models.CharField(max_length=998, blank=True, db_index=True)
    
    # Status & Resolution
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="received", db_index=True)
    directory_user = models.ForeignKey('LexUser', null=True, blank=True, on_delete=models.SET_NULL)
    policy_applied = models.ForeignKey('Policy', null=True, blank=True, on_delete=models.SET_NULL)
    
    # Forensic Meta
    is_reply = models.BooleanField(default=False)
    processing_notes = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant", "status", "created_at"]),
            models.Index(fields=["trn", "sender"]),
        ]

    def __str__(self):
        return f"{self.trn} | {self.trigger_type} | {self.status}"

class TransactionEvent(TimeStampedModel):
    """Immutable-ish events for granular traceability."""
    transaction = models.ForeignKey(TransactionLog, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=50, db_index=True) # e.g., 'MIME_PARSED', 'GRAPH_AUTH_SUCCESS'
    level = models.CharField(max_length=10, choices=[('info', 'Info'), ('warn', 'Warning'), ('error', 'Error')], default='info')
    message = models.TextField()
    metadata = models.JSONField(default=dict, blank=True) # Store raw API errors or header snippets

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.transaction.trn} | {self.event_type}"