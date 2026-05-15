---
name: connect-gcp
description: Connect to a GCP project, validate credentials, and discover what services are in use.
user-invocable: true
---

# Connect GCP

You are helping a semi-technical founder connect Shasta to their Google Cloud project for SOC 2 and ISO 27001 compliance scanning.

## Configuration

Shasta uses `shasta.config.json` in the project root for all settings. Before running any commands, check if this file has `gcp_project_id` set. If not, you'll need to configure it.

## What to do

1. **Check that the GCP SDK extra is installed.** The GCP check modules need the `[gcp]` optional dependencies (`google-auth`, `google-api-python-client`, `google-cloud-storage`). Test with:
   ```bash
   <PYTHON_CMD> -c "import google.auth, googleapiclient, google.cloud.storage; print('gcp deps OK')"
   ```
   If that fails with `ModuleNotFoundError`, install them: `pip install -e ".[gcp]"`

2. **Check if shasta.config.json is configured for GCP.** Read the file. If `gcp_project_id` is empty, ask the user:
   - Have you run `gcloud auth application-default login`? If not, tell them to run `! gcloud auth application-default login` first. This sets up Application Default Credentials (ADC) — the same mechanism a service account or Workload Identity would use.
   - Run `gcloud config get-value project` to get their current project ID. If they have several, `gcloud projects list` shows all of them.
   - What region are their resources in? (e.g., `us-central1`, `us-east1`, `europe-west1`) — default: `us-central1`
   - If `company_name` is still empty, ask for it too.

   Update `shasta.config.json` with their answers — set `gcp_project_id` and `gcp_region`.

3. **Also detect the correct Python command** if `python_cmd` isn't set. Run `python3 --version` and `python --version` to find which works. Update `python_cmd` in the config.

4. **Validate GCP credentials** by running (substitute the correct python command):
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import get_gcp_client
   c = get_gcp_client()
   info = c.validate_credentials()
   services = c.discover_services()
   print(f'GCP Project: {info.project_name} ({info.project_id})')
   print(f'Project Number: {info.project_number}')
   print(f'Principal: {info.principal}')
   print(f'Region: {info.region}')
   print(f'Services detected: {services if services else \"none (empty project)\"}')
   "
   ```

5. **Initialize the Shasta database** (if not already done):
   ```bash
   <PYTHON_CMD> -c "from shasta.db.schema import ShastaDB; db = ShastaDB(); db.initialize(); print('Database initialized at data/shasta.db')"
   ```

6. **Present results** in a clear, friendly format and suggest running `/scan` next.

## Important notes

- **Never ask the user to paste GCP credentials or service account keys into the chat.** Always use `gcloud auth application-default login` or the `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing at a key file.
- Replace `<PYTHON_CMD>` with whatever works on this machine (`python3`, `python`, or `py -3.12`).
- If credentials fail, guide them through `gcloud auth application-default login` or check that the active project is set with `gcloud config set project <PROJECT_ID>`.
- GCP scanning requires read access. The `roles/viewer` (Project Viewer) basic role is sufficient for all checks; `roles/iam.securityReviewer` covers the IAM-policy checks if Viewer is too broad for the org.
- Some checks (org-policy, audit-log config) require APIs to be enabled — `cloudresourcemanager.googleapis.com`, `serviceusage.googleapis.com`, `compute.googleapis.com`. Missing APIs produce NOT_ASSESSED findings, which is fine.
