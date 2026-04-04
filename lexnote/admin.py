from django.contrib import admin
from .models import Tenant, TenantDomain, SignatureTemplate, SignaturePolicy, DirectoryUser, TransactionLog

@admin.register(TransactionLog)
class TransactionLogAdmin(admin.ModelAdmin):
    list_display = ('trn', 'sender', 'status', 'timestamp')
    readonly_fields = ('trn', 'message_id', 'sender', 'recipient', 'status', 'processing_notes', 'timestamp')
    search_fields = ('trn', 'sender', 'message_id')
    list_filter = ('status', 'tenant')

admin.site.register(Tenant)
admin.site.register(TenantDomain)
admin.site.register(SignatureTemplate)
admin.site.register(SignaturePolicy)
admin.site.register(DirectoryUser)