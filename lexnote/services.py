import requests
from .models import DirectoryUser

class MicrosoftGraphService:
    def __init__(self, tenant):
        self.tenant = tenant
        self.token = self._get_access_token()

    def _get_access_token(self):
        url = f"https://login.microsoftonline.com/{self.tenant.microsoft_tenant_id}/oauth2/v2.0/token"
        data = {
            'client_id': self.tenant.client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': self.tenant.client_secret,
            'grant_type': 'client_credentials',
        }
        response = requests.post(url, data=data).json()
        return response.get('access_token')

    def sync_users(self):
        if not self.token:
            return 0
        
        url = "https://graph.microsoft.com/v1.0/users?$select=displayName,mail,jobTitle,businessPhones"
        headers = {'Authorization': f'Bearer {self.token}'}
        users_data = requests.get(url, headers=headers).json().get('value', [])

        # 1. Track emails found in this sync cycle
        synced_emails = []
        count = 0

        for data in users_data:
            email = data.get('mail')
            if email:
                email_lower = email.lower()
                synced_emails.append(email_lower)
                
                # Update or create active users
                user, created = DirectoryUser.objects.update_or_create(
                    tenant=self.tenant,
                    email=email_lower,
                    defaults={
                        'first_name': data.get('displayName', ''),
                        'job_title': data.get('jobTitle', ''),
                        'phone_number': data.get('businessPhones', [None])[0],
                        'is_active': True # Ensure they are active if found in Graph
                    }
                )
                count += 1

        # 2. Deactivate users NOT in the synced_emails list
        # This keeps the records for audit/logs but prevents them from getting signatures
        DirectoryUser.objects.filter(tenant=self.tenant).exclude(email__in=synced_emails).update(is_active=False)

        return count