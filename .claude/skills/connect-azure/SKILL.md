---
name: connect-azure
description: Connect to an Azure subscription, validate credentials, and discover what services are in use.
user-invocable: true
---

# Connect Azure

You are helping a semi-technical founder connect Shasta to their Azure subscription for SOC 2 and ISO 27001 compliance scanning.

## Configuration

Shasta uses `shasta.config.json` in the project root for all settings. Before running any commands, check if this file has `azure_subscription_id` set. If not, you'll need to configure it.

## What to do

1. **Check if shasta.config.json is configured for Azure.** Read the file. If `azure_subscription_id` is empty, ask the user:
   - Have you run `az login`? If not, tell them to run `! az login` first.
   - Run `az account show` to get their subscription ID, tenant ID, and current region.
   - What region are their resources in? (e.g., `centralindia`, `eastus`, `westeurope`)
   - If `company_name` is still empty, ask for it too.
   
   Update `shasta.config.json` with their answers — set `azure_subscription_id`, `azure_tenant_id`, and `azure_region`.

2. **Also detect the correct Python command** if `python_cmd` isn't set. Run `python3 --version` and `python --version` to find which works. Update `python_cmd` in the config.

3. **Validate Azure credentials** by running (substitute the correct python command):
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import get_azure_client
   c = get_azure_client()
   info = c.validate_credentials()
   services = c.discover_services()
   print(f'Azure Subscription: {info.subscription_name} ({info.subscription_id})')
   print(f'Tenant: {info.tenant_id}')
   print(f'Identity: {info.user_principal}')
   print(f'Region: {info.region}')
   print(f'Services detected: {services if services else \"none (empty subscription)\"}')
   "
   ```

4. **Initialize the Shasta database** (if not already done):
   ```bash
   <PYTHON_CMD> -c "from shasta.db.schema import ShastaDB; db = ShastaDB(); db.initialize(); print('Database initialized at data/shasta.db')"
   ```

5. **Present results** in a clear, friendly format and suggest running `/scan` next.

## Important notes

- **Never ask the user to paste Azure credentials into the chat.** Always use `az login` or service principal environment variables.
- Replace `<PYTHON_CMD>` with whatever works on this machine (`python3`, `python`, or `py -3.12`).
- If credentials fail, guide them through `az login` or `az account set --subscription <ID>`.
- Azure scanning requires read access. The user's default role (Reader or Contributor) is sufficient for all checks.
- Entra ID checks (Conditional Access, user enumeration) require Graph API permissions — these may produce NOT_ASSESSED findings if permissions are missing, which is fine.
