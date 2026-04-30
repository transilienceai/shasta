"""GCP client for Shasta compliance scanning.

Wraps the Google Cloud API client to provide validated access to GCP services.
Mirrors the AWSClient / AzureClient interface for consistency.

Supports all standard Application Default Credentials (ADC) sources:
- gcloud CLI (gcloud auth application-default login)
- Service account JSON key (GOOGLE_APPLICATION_CREDENTIALS env var)
- Workload Identity (running on GCP: GCE, GKE, Cloud Run, etc.)
- IAM service account impersonation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class GCPClientError(Exception):
    """Raised when GCP client operations fail."""


@dataclass
class GCPProjectInfo:
    """Information about the connected GCP project."""

    project_id: str
    project_number: str
    project_name: str
    principal: str
    region: str
    services_in_use: list[str] = field(default_factory=list)


# Default region used when none is specified
_DEFAULT_REGION = "us-central1"

# Fallback region list when the Compute API is unavailable
_FALLBACK_REGIONS = [
    "us-central1",
    "us-east1",
    "us-west1",
    "europe-west1",
    "asia-east1",
]


class GCPClient:
    """Manages GCP API credentials and provides validated access to GCP services.

    Uses Application Default Credentials (ADC), which supports:
    - gcloud CLI: ``gcloud auth application-default login``
    - Service Account: ``GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json``
    - Workload Identity: automatically picked up when running on GCP
    - Explicit credentials passed to the constructor
    """

    def __init__(
        self,
        project_id: str | None = None,
        credentials: Any = None,
        region: str | None = None,
    ):
        self._project_id = project_id
        self._credentials = credentials
        self._region = region or _DEFAULT_REGION
        self._account_info: GCPProjectInfo | None = None
        self._service_cache: dict[str, Any] = {}

    @property
    def credentials(self) -> Any:
        """Lazy-initialize Application Default Credentials."""
        if self._credentials is None:
            try:
                import google.auth

                self._credentials, project_id = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                if not self._project_id and project_id:
                    self._project_id = project_id
            except ImportError:
                raise GCPClientError("GCP SDK not installed. Run: pip install -e '.[gcp]'")
            except Exception as e:
                raise GCPClientError(f"Failed to obtain GCP credentials: {e}")
        return self._credentials

    @property
    def project_id(self) -> str:
        if self._account_info:
            return self._account_info.project_id
        if self._project_id:
            return self._project_id
        raise GCPClientError(
            "No GCP project ID available. Run validate_credentials() first or "
            "set GOOGLE_CLOUD_PROJECT environment variable."
        )

    @property
    def account_info(self) -> GCPProjectInfo | None:
        return self._account_info

    def service(self, service_name: str, version: str) -> Any:
        """Return a cached googleapiclient discovery service.

        Usage:
            iam = client.service("iam", "v1")
            response = iam.projects().serviceAccounts().list(name=...).execute()
        """
        key = f"{service_name}/{version}"
        if key not in self._service_cache:
            try:
                from googleapiclient import discovery

                self._service_cache[key] = discovery.build(
                    service_name,
                    version,
                    credentials=self.credentials,
                    cache_discovery=False,
                )
            except ImportError:
                raise GCPClientError(
                    "google-api-python-client not installed. Run: pip install -e '.[gcp]'"
                )
        return self._service_cache[key]

    def storage_client(self) -> Any:
        """Return a google.cloud.storage.Client for GCS operations."""
        key = "_storage_client"
        if key not in self._service_cache:
            try:
                from google.cloud import storage

                self._service_cache[key] = storage.Client(
                    project=self._project_id,
                    credentials=self.credentials,
                )
            except ImportError:
                raise GCPClientError(
                    "google-cloud-storage not installed. Run: pip install -e '.[gcp]'"
                )
        return self._service_cache[key]

    def validate_credentials(self) -> GCPProjectInfo:
        """Validate GCP credentials and discover project information.

        Returns GCPProjectInfo with project ID, number, and principal details.
        """
        try:
            crm = self.service("cloudresourcemanager", "v3")
            if not self._project_id:
                # Try to infer project from credentials scope
                try:
                    import google.auth.transport.requests

                    request = google.auth.transport.requests.Request()
                    self.credentials.refresh(request)
                    # For service accounts the quota_project_id may be set
                    self._project_id = getattr(
                        self.credentials, "quota_project_id", None
                    ) or getattr(self.credentials, "project_id", None)
                except Exception:
                    pass

            if not self._project_id:
                raise GCPClientError(
                    "No GCP project ID found. Set GOOGLE_CLOUD_PROJECT or pass "
                    "project_id to GCPClient()."
                )

            project = crm.projects().get(name=f"projects/{self._project_id}").execute()
            principal = self._get_principal()

            self._account_info = GCPProjectInfo(
                project_id=self._project_id,
                project_number=project.get("name", "").replace("projects/", "")
                or project.get("projectNumber", "")
                or self._project_id,
                project_name=project.get("displayName", self._project_id),
                principal=principal,
                region=self._region,
            )
            return self._account_info

        except GCPClientError:
            raise
        except Exception as e:
            raise GCPClientError(f"Failed to validate GCP credentials: {e}")

    def _get_principal(self) -> str:
        """Extract the principal (email/service-account) from credentials."""
        try:
            creds = self.credentials
            # Service account credentials have a service_account_email attribute
            if hasattr(creds, "service_account_email"):
                return creds.service_account_email
            # OAuth user credentials
            if hasattr(creds, "token"):
                import base64
                import json

                # Attempt to decode the token
                token = getattr(creds, "id_token", None) or getattr(creds, "token", None)
                if token and "." in str(token):
                    payload = str(token).split(".")[1]
                    payload += "=" * (4 - len(payload) % 4)
                    claims = json.loads(base64.b64decode(payload))
                    return claims.get("email") or claims.get("sub") or "unknown"
        except Exception:
            pass
        return "unknown"

    def list_projects(self) -> list[dict[str, str]]:
        """List all GCP projects accessible to this credential.

        Returns a list of {project_id, display_name, project_number, state} dicts.
        Best-effort; returns the current single project on failure.
        """
        try:
            crm = self.service("cloudresourcemanager", "v3")
            out: list[dict[str, str]] = []
            page_token = None
            while True:
                kwargs: dict[str, Any] = {}
                if page_token:
                    kwargs["pageToken"] = page_token
                response = crm.projects().list(**kwargs).execute()
                for p in response.get("projects", []):
                    if p.get("state") != "ACTIVE":
                        continue
                    out.append(
                        {
                            "project_id": p.get("projectId", ""),
                            "display_name": p.get("displayName", ""),
                            "project_number": p.get("name", "").replace("projects/", ""),
                            "state": p.get("state", ""),
                        }
                    )
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            return out
        except Exception:
            pid = self._project_id or "unknown"
            return [
                {"project_id": pid, "display_name": "", "project_number": "", "state": "ACTIVE"}
            ]

    def for_project(self, project_id: str) -> "GCPClient":
        """Return a sibling GCPClient bound to a different project.

        Reuses the same credentials and clears the service cache so each project
        gets fresh API clients.
        """
        sibling = GCPClient(
            project_id=project_id,
            credentials=self._credentials,
            region=self._region,
        )
        return sibling

    def for_region(self, region: str) -> "GCPClient":
        """Return a sibling GCPClient scoped to a specific region.

        The region is stored for use by regional API calls (subnets, instances).
        Credentials and project are shared.
        """
        sibling = GCPClient(
            project_id=self._project_id,
            credentials=self._credentials,
            region=region,
        )
        sibling._account_info = self._account_info
        return sibling

    def get_enabled_regions(self) -> list[str]:
        """Return all available GCP compute regions for this project."""
        try:
            compute = self.service("compute", "v1")
            response = compute.regions().list(project=self.project_id).execute()
            return sorted(r["name"] for r in response.get("items", []) if r.get("status") == "UP")
        except Exception:
            return list(_FALLBACK_REGIONS)

    def discover_services(self) -> list[str]:
        """Discover which GCP services are in use in the project.

        Queries the Service Usage API for enabled APIs.
        Best-effort; returns an empty list on failure.
        """
        services: list[str] = []
        try:
            su = self.service("serviceusage", "v1")
            name = f"projects/{self.project_id}"
            page_token = None
            while True:
                kwargs: dict[str, Any] = {"parent": name, "filter": "state:ENABLED"}
                if page_token:
                    kwargs["pageToken"] = page_token
                response = su.services().list(**kwargs).execute()
                for svc in response.get("services", []):
                    svc_name = svc.get("name", "").split("/")[-1]
                    services.append(svc_name)
                page_token = response.get("nextPageToken")
                if not page_token:
                    break

            if self._account_info:
                self._account_info.services_in_use = services
        except Exception:
            pass
        return services

    def to_dict(self) -> dict[str, Any]:
        """Serialize connection info for reporting."""
        if not self._account_info:
            return {"status": "not_connected"}
        return {
            "project_id": self._account_info.project_id,
            "project_name": self._account_info.project_name,
            "principal": self._account_info.principal,
            "region": self._account_info.region,
            "services_in_use": self._account_info.services_in_use,
        }
