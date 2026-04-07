"""Azure client for Shasta compliance scanning.

Wraps the Azure SDK to provide validated access to Azure services.
Mirrors the AWSClient interface for consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class AzureClientError(Exception):
    """Raised when Azure client operations fail."""


@dataclass
class AzureAccountInfo:
    """Information about the connected Azure subscription."""

    subscription_id: str
    subscription_name: str
    tenant_id: str
    user_principal: str
    region: str
    services_in_use: list[str] = field(default_factory=list)


class AzureClient:
    """Manages Azure SDK credentials and provides validated access to Azure services.

    Uses DefaultAzureCredential which supports:
    - Azure CLI (az login)
    - Managed Identity (VM, App Service, etc.)
    - Service Principal (env vars: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
    - Visual Studio Code credential
    """

    def __init__(
        self,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        region: str | None = None,
    ):
        self._subscription_id = subscription_id
        self._tenant_id = tenant_id
        self._region = region or "eastus"
        self._credential: Any = None
        self._account_info: AzureAccountInfo | None = None
        self._mgmt_clients: dict[str, Any] = {}

    @property
    def credential(self) -> Any:
        """Lazy-initialize DefaultAzureCredential."""
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential

                self._credential = DefaultAzureCredential()
            except ImportError:
                raise AzureClientError("Azure SDK not installed. Run: pip install -e '.[azure]'")
            except Exception as e:
                raise AzureClientError(f"Failed to create Azure credential: {e}")
        return self._credential

    @property
    def account_info(self) -> AzureAccountInfo | None:
        return self._account_info

    @property
    def subscription_id(self) -> str:
        """Get subscription ID from account info or config."""
        if self._account_info:
            return self._account_info.subscription_id
        if self._subscription_id:
            return self._subscription_id
        raise AzureClientError("No subscription ID available. Run validate_credentials() first.")

    def validate_credentials(self) -> AzureAccountInfo:
        """Validate Azure credentials and discover subscription info.

        Returns AzureAccountInfo with subscription and tenant details.
        """
        try:
            from azure.mgmt.subscription import SubscriptionClient
        except ImportError:
            raise AzureClientError("Azure SDK not installed. Run: pip install -e '.[azure]'")

        try:
            sub_client = SubscriptionClient(self.credential)

            if self._subscription_id:
                sub = sub_client.subscriptions.get(self._subscription_id)
            else:
                # Use the first available subscription
                subs = list(sub_client.subscriptions.list())
                if not subs:
                    raise AzureClientError("No Azure subscriptions found for this credential.")
                sub = subs[0]
                self._subscription_id = sub.subscription_id

            # Get tenant ID from subscription if not provided
            if not self._tenant_id:
                self._tenant_id = getattr(sub, "tenant_id", None) or ""

            # Get user principal name from the token
            user_principal = self._get_user_principal()

            self._account_info = AzureAccountInfo(
                subscription_id=sub.subscription_id,
                subscription_name=sub.display_name or "",
                tenant_id=self._tenant_id or getattr(sub, "tenant_id", "") or "",
                user_principal=user_principal,
                region=self._region,
            )
            return self._account_info

        except AzureClientError:
            raise
        except Exception as e:
            raise AzureClientError(f"Failed to validate Azure credentials: {e}")

    def _get_user_principal(self) -> str:
        """Extract user principal from the credential token."""
        try:
            import base64
            import json

            token = self.credential.get_token("https://management.azure.com/.default")
            # Decode JWT payload (second segment)
            payload = token.token.split(".")[1]
            # Add padding
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(base64.b64decode(payload))
            return claims.get("upn") or claims.get("unique_name") or claims.get("oid", "unknown")
        except Exception:
            return "unknown"

    def discover_services(self) -> list[str]:
        """Discover which Azure services are in use in the subscription.

        Queries the Resource Graph to find resource types present.
        """
        services: list[str] = []
        try:
            from azure.mgmt.resource import ResourceManagementClient

            resource_client = ResourceManagementClient(self.credential, self.subscription_id)

            # List resource providers that have resources
            resource_types_seen: set[str] = set()
            for resource in resource_client.resources.list():
                if resource.type:
                    provider = resource.type.split("/")[0]
                    resource_types_seen.add(provider)

            # Map Azure providers to friendly service names
            provider_map = {
                "Microsoft.Compute": "compute",
                "Microsoft.Network": "networking",
                "Microsoft.Storage": "storage",
                "Microsoft.Sql": "sql",
                "Microsoft.KeyVault": "keyvault",
                "Microsoft.Web": "appservice",
                "Microsoft.ContainerService": "aks",
                "Microsoft.ContainerRegistry": "acr",
                "Microsoft.OperationalInsights": "log-analytics",
                "Microsoft.Insights": "monitor",
                "Microsoft.Security": "defender",
                "Microsoft.Authorization": "rbac",
            }

            for provider in sorted(resource_types_seen):
                friendly = provider_map.get(provider, provider.split(".")[-1].lower())
                services.append(friendly)

            if self._account_info:
                self._account_info.services_in_use = services

        except Exception:
            # Service discovery is best-effort
            pass

        return services

    def mgmt_client(self, client_class: type, **kwargs: Any) -> Any:
        """Factory for Azure management clients.

        Caches clients by class name to avoid re-creating them.

        Usage:
            from azure.mgmt.compute import ComputeManagementClient
            compute = client.mgmt_client(ComputeManagementClient)
        """
        key = client_class.__name__
        if key not in self._mgmt_clients:
            self._mgmt_clients[key] = client_class(self.credential, self.subscription_id, **kwargs)
        return self._mgmt_clients[key]

    def graph_client(self) -> Any:
        """Get a Microsoft Graph client for Entra ID queries.

        Returns a GraphServiceClient from the msgraph-sdk package.
        Note: Graph SDK is async — use graph_call() to invoke methods.
        """
        key = "_graph_client"
        if key not in self._mgmt_clients:
            try:
                from msgraph import GraphServiceClient

                self._mgmt_clients[key] = GraphServiceClient(self.credential)
            except ImportError:
                raise AzureClientError(
                    "Microsoft Graph SDK not installed. Run: pip install msgraph-sdk"
                )
        return self._mgmt_clients[key]

    def graph_call(self, coro: Any) -> Any:
        """Run an async Microsoft Graph API call synchronously.

        The msgraph-sdk is async-only; this helper runs coroutines in a
        persistent event loop so the HTTP client can reuse connections.

        Usage:
            graph = client.graph_client()
            result = client.graph_call(graph.users.get())
        """
        import asyncio

        if not hasattr(self, "_graph_loop") or self._graph_loop is None:
            self._graph_loop = asyncio.new_event_loop()

        return self._graph_loop.run_until_complete(coro)

    def close(self) -> None:
        """Close the client and release resources (event loop, cached clients)."""
        if hasattr(self, "_graph_loop") and self._graph_loop is not None:
            self._graph_loop.close()
            self._graph_loop = None
        self._mgmt_clients.clear()
        self._credential = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def to_dict(self) -> dict[str, Any]:
        """Serialize connection info for reporting."""
        if not self._account_info:
            return {"status": "not_connected"}
        return {
            "subscription_id": self._account_info.subscription_id,
            "subscription_name": self._account_info.subscription_name,
            "tenant_id": self._account_info.tenant_id,
            "user_principal": self._account_info.user_principal,
            "region": self._account_info.region,
            "services_in_use": self._account_info.services_in_use,
        }
