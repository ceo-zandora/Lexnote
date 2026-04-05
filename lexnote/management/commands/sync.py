import asyncio
from django.core.management.base import BaseCommand
from asgiref.sync import sync_to_async
from django.utils import timezone
from lexnote.models import Tenant, LexUser, Group, TransactionLog, TransactionEvent
from lexnote.utils import GraphClient

class Command(BaseCommand):
    help = 'M365 Tenant Sync Engine with Forensic Tracing and Soft-Delete'

    def handle(self, *args, **options):
        """Entry point: Runs the async loop."""
        try:
            asyncio.run(self.sync_all())
        except Exception as e:
            self.stderr.write(f"CRITICAL SYNC FAILURE: {str(e)}")

    async def sync_all(self):
        get_tenants = sync_to_async(lambda: list(Tenant.objects.filter(is_active=True)))
        tenants = await get_tenants()

        for t in tenants:
            client = GraphClient(t)
            
            # Tracking IDs for Soft-Delete Sweep
            synced_user_ids = []
            synced_group_ids = []
            stats = {'u': 0, 'g': 0}
            
            tx = await self.start_sync_transaction(t)
            
            try:
                # 1. Auth Trace
                await self.log_event(tx, 'directory_lookup_started', f"Initiating Graph API sync for {t.name}")
                await client.get_token()
                await self.log_event(tx, 'relay_validated', "Graph API Authentication Successful")

                # 2. Sync Users
                users_data = await client.fetch_users()
                for u in users_data:
                    user_obj = await self.process_user(t, u)
                    synced_user_ids.append(user_obj.id)
                    stats['u'] += 1
                
                # 3. Sync Groups
                groups_data = await client.fetch_groups()
                for g in groups_data:
                    group_obj = await self.process_group(t, g)
                    synced_group_ids.append(group_obj.id)
                    
                    # 4. Sync Memberships
                    member_ids = await client.fetch_group_members(g['id'])
                    await self.update_memberships(group_obj, member_ids)
                    stats['g'] += 1

                # 5. Lifecycle Sweep (Soft Delete)
                # Mark users/groups NOT found in this sync as inactive
                await self.lifecycle_sweep(t, synced_user_ids, synced_group_ids, tx)

                # 6. Finalize Transaction
                tx.status = 'sync_success' # Updated as per your requirement
                tx.processing_notes = f"Sync Completed: {stats['u']} Users, {stats['g']} Groups processed."
                tx.processed_at = timezone.now()
                await sync_to_async(tx.save)()
                await self.log_event(tx, 'processing_completed', "Full Lifecycle Sync Finished")

                # 7. Update Tenant Metadata
                t.last_sync = timezone.now()
                await sync_to_async(t.save)()
                
            
            except Exception as e:
                tx.status = 'sync_fail'
                tx.error_message = str(e)
                tx.processed_at = timezone.now()
                await sync_to_async(tx.save)()
                
                await self.log_event(
                    tx, 
                    'processing_failed', 
                    f"Sync aborted: {str(e)}", 
                    level='error'
                )
                self.stderr.write(f"Error syncing tenant {t.name}: {str(e)}")

    @sync_to_async
    def start_sync_transaction(self, tenant):
        return TransactionLog.objects.create(
            tenant=tenant,
            trigger_type='SYNC',
            status='processing',
            sender="SYSTEM"
        )
    
    @sync_to_async
    def log_event(self, tx, event_type, message, level='info', meta=None):
        TransactionEvent.objects.create(
            transaction=tx,
            event_type=event_type,
            level=level,
            message=message,
            metadata=meta or {}
        )

    @sync_to_async
    def process_user(self, tenant, u):
        biz_phones = u.get('businessPhones', [])
        office_phone = biz_phones[0] if biz_phones else None
        
        user_obj, _ = LexUser.objects.update_or_create(
            external_id=u['id'],
            tenant=tenant,
            defaults={
                'email': u.get('mail') or u.get('userPrincipalName'),
                'upn': u.get('userPrincipalName'),
                'display_name': u.get('displayName'),
                'first_name': u.get('givenName'),
                'last_name': u.get('surname'),
                'designation': u.get('jobTitle'),
                'department': u.get('department'),
                'employee_id': u.get('employeeId'),
                'company_name': u.get('companyName'),
                'office_location': u.get('officeLocation'),
                'city': u.get('city'),
                'state': u.get('state'),
                'mobile_phone': u.get('mobilePhone'),
                'fax_number': u.get('faxNumber'),
                'office_phone': office_phone,
                'is_active': True, # Re-activate if they returned to the tenant
            }
        )
        return user_obj
    
    @sync_to_async
    def process_group(self, tenant, g):
        group_obj, _ = Group.objects.update_or_create(
            external_id=g['id'],
            tenant=tenant,
            defaults={
                'display_name': g.get('displayName'),
                'mail_enabled': g.get('mailEnabled', False),
                'security_enabled': g.get('securityEnabled', False),
                'is_active': True,
            }
        )
        return group_obj
    
    @sync_to_async
    def update_memberships(self, group_obj, member_ids):
        users_in_group = LexUser.objects.filter(
            tenant=group_obj.tenant, 
            external_id__in=member_ids
        )
        group_obj.members.set(users_in_group)

    @sync_to_async
    def lifecycle_sweep(self, tenant, synced_user_ids, synced_group_ids, tx):
        """Identifies and deactivates orphaned records."""
        
        # Deactivate Users
        deactivated_users = LexUser.objects.filter(
            tenant=tenant, 
            is_active=True
        ).exclude(id__in=synced_user_ids).update(is_active=False)
        
        # Deactivate Groups
        deactivated_groups = Group.objects.filter(
            tenant=tenant, 
            is_active=True
        ).exclude(id__in=synced_group_ids).update(is_active=False)

        if deactivated_users > 0 or deactivated_groups > 0:
            TransactionEvent.objects.create(
                transaction=tx,
                event_type='policy_not_matched', # Using this for 'de-provisioning' trace
                level='info',
                message=f"Lifecycle Sweep: Deactivated {deactivated_users} users and {deactivated_groups} groups (not found in M365)."
            )