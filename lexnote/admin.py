from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.utils.html import format_html
from .models import Tenant, Group, LexUser, SignatureTemplate, Policy, TransactionEvent, TransactionLog

# --- Inlines for better UX ---

class GroupInline(admin.TabularInline):
    model = Group
    extra = 0
    fields = ('display_name', 'mail_enabled', 'security_enabled')
    readonly_fields = ('external_id',)

class UserInline(admin.TabularInline):
    model = LexUser
    extra = 0
    fields = ('display_name', 'email', 'designation')
    readonly_fields = ('external_id', 'email')

# --- Admin Classes ---

@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant_id', 'relay_domain', 'is_active', 'last_sync_status')
    list_filter = ('is_active',)
    search_fields = ('name', 'tenant_id', 'relay_domain')
    inlines = [GroupInline]
    
    def last_sync_status(self, obj):
        return obj.last_sync if obj.last_sync else "Never Synced"
    last_sync_status.short_description = "Last Successful Sync"

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('display_name', 'tenant', 'mail_enabled', 'security_enabled', 'member_count')
    list_filter = ('tenant', 'mail_enabled', 'security_enabled')
    search_fields = ('display_name', 'external_id')
    
    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = "Members"

@admin.register(LexUser)
class LexUserAdmin(admin.ModelAdmin):
    list_display = ('display_name', 'email', 'tenant', 'designation', 'department', 'city')
    list_filter = ('tenant', 'department', 'city')
    search_fields = ('display_name', 'email', 'employee_id', 'upn')
    readonly_fields = ('external_id',)
    filter_horizontal = ('groups',) # Easier management of group memberships
    
    fieldsets = (
        ('Identity', {
            'fields': ('tenant', 'external_id', 'display_name', 'first_name', 'last_name', 'email', 'upn')
        }),
        ('Professional', {
            'fields': ('employee_id', 'designation', 'department', 'company_name')
        }),
        ('Contact & Location', {
            'fields': ('mobile_phone', 'office_phone', 'office_location', 'city', 'state', 'fax_number')
        }),
        ('Relationships', {
            'fields': ('groups',)
        }),
    )

@admin.register(SignatureTemplate)
class SignatureTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'preview_template')
    search_fields = ('name',)
    
    def preview_template(self, obj):
        # Provides a safe visual snippet in the list view
        return format_html('<code style="color: #666;">{}...</code>', obj.html_content[:50])

@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ('priority', 'name', 'tenant', 'is_active')
    
    # Add this line to move the link from 'priority' to 'name'
    list_display_links = ('name',) 
    
    list_editable = ('priority', 'is_active')
    
    fieldsets = (
        ('General Information', {
            'fields': ('name', 'tenant', 'priority', 'is_active')
        }),
        ('Targeting (Inclusions)', {
            'fields': (
                'target_users', 'target_groups', 
                'target_departments', 'target_companies', 
                'target_cities', 'target_states', 'target_office_locations'
            )
        }),
        ('Exclusions (Overrides)', {
            'fields': ('exclude_users', 'exclude_groups', 'exclude_departments')
        }),
        ('Signatures', {
            'fields': ('initial_signature', 'reply_signature')
        }),
    )
    filter_horizontal = ('target_users', 'target_groups', 'exclude_users', 'exclude_groups')

class TransactionEventInline(admin.TabularInline):
    model = TransactionEvent
    extra = 0
    readonly_fields = ('event_type', 'level', 'message', 'metadata', 'created_at')
    can_delete = False

@admin.register(TransactionLog)
class TransactionLogAdmin(admin.ModelAdmin):
    list_display = ('trn', 'trigger_type', 'tenant', 'status', 'created_at', 'processed_at')
    list_filter = ('trigger_type', 'status', 'tenant')
    search_fields = ('trn', 'sender', 'internet_message_id')
    inlines = [TransactionEventInline]
    
    readonly_fields = [
        f.name for f in TransactionLog._meta.get_fields() 
        if not f.is_relation or f.one_to_one or f.many_to_one
    ]
    
    def has_add_permission(self, request): 
        return False