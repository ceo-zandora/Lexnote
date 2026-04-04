from django.core.management.base import BaseCommand
from lexnote.models import Tenant
from lexnote.services import MicrosoftGraphService

class Command(BaseCommand):
    help = 'Syncs all active tenants with Microsoft Graph'

    def handle(self, *args, **options):
        tenants = Tenant.objects.filter(is_active=True)
        for tenant in tenants:
            if tenant.client_id and tenant.client_secret:
                self.stdout.write(f"Syncing {tenant.name}...")
                svc = MicrosoftGraphService(tenant)
                count = svc.sync_users()
                self.stdout.write(self.style.SUCCESS(f"Synced {count} users."))