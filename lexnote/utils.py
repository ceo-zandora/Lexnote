import httpx
import logging

logger = logging.getLogger('lexnote.sync')

class GraphClient:
    def __init__(self, tenant):
        self.tenant = tenant
        self.token = None

    async def get_token(self):
        url = f"https://login.microsoftonline.com/{self.tenant.tenant_id}/oauth2/v2.0/token"
        data = {
            'client_id': self.tenant.client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': self.tenant.client_secret,
            'grant_type': 'client_credentials',
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(url, data=data)
            r.raise_for_status()
            self.token = r.json().get('access_token')

    async def fetch_users(self):
        if not self.token: await self.get_token()
        url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,givenName,surname,userPrincipalName,mail,jobTitle,department,city,state,mobilePhone,businessPhones,faxNumber,employeeId,companyName,officeLocation"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers)
            return r.json().get('value', [])
        
    async def fetch_groups(self):
        """Fetches all groups from the tenant."""
        if not self.token: await self.get_token()
        url = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mailEnabled,securityEnabled"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers)
            return r.json().get('value', [])
        
    async def fetch_group_members(self, group_id):
        """Fetches member IDs for a specific group."""
        if not self.token: await self.get_token()
        # We only need the IDs to match against our existing LexUser records
        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=id"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers)
            # Returns a list of IDs of users/groups/devices in that group
            return [m['id'] for m in r.json().get('value', []) if '@odata.type' in m and 'user' in m['@odata.type']]