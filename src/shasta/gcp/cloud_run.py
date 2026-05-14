"""GCP Cloud Run security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.1 — Authentication and access control (unauthenticated invocation)
  CC6.2 — Service account least privilege
  CC6.6 — System boundaries (ingress controls, binary authorization)
  CC6.7 — Data protection (secrets management, environment variables)

Cloud Run v2 API is used via ``client.service("run", "v2")``.
Each service is inspected per region (Cloud Run is regional).
Engineering Principle #3: regional checks iterate get_enabled_regions().
"""

from __future__ import annotations

import re
from typing import Any

from shasta.gcp.client import GCPClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

IS_GLOBAL = False  # Cloud Run services are regional

# Ingress settings that restrict access — anything other than "INGRESS_TRAFFIC_ALL"
_RESTRICTED_INGRESS = {
    "INGRESS_TRAFFIC_INTERNAL_ONLY",
    "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
}

# Default Compute Engine SA — should not be used by Cloud Run services
_DEFAULT_COMPUTE_SA_PATTERN = re.compile(r"^\d+-compute@developer\.gserviceaccount\.com$")

# Environment variable name patterns that suggest embedded secrets
_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api_?key|auth_?token|private_?key|credential|access_?token)",
    re.IGNORECASE,
)


def run_all_gcp_cloud_run_checks(client: GCPClient) -> list[Finding]:
    """Run all Cloud Run compliance checks across all enabled regions."""
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []
    for region in client.get_enabled_regions():
        regional_client = client.for_region(region)
        findings.extend(check_cloud_run_no_unauthenticated_access(regional_client, project_id, region))
        findings.extend(check_cloud_run_no_default_service_account(regional_client, project_id, region))
        findings.extend(check_cloud_run_ingress_restricted(regional_client, project_id, region))
        findings.extend(check_cloud_run_binary_authorization(regional_client, project_id, region))
        findings.extend(check_cloud_run_no_plaintext_secrets(regional_client, project_id, region))

    return findings


def _list_cloud_run_services(client: GCPClient, project_id: str, region: str) -> list[dict[str, Any]]:
    """Return all Cloud Run v2 services in the given region."""
    run = client.service("run", "v2")
    parent = f"projects/{project_id}/locations/{region}"
    response = run.projects().locations().services().list(parent=parent).execute()
    services = response.get("services", [])

    # Paginate
    next_page = response.get("nextPageToken")
    while next_page:
        response = (
            run.projects()
            .locations()
            .services()
            .list(parent=parent, pageToken=next_page)
            .execute()
        )
        services.extend(response.get("services", []))
        next_page = response.get("nextPageToken")

    return services


def check_cloud_run_no_unauthenticated_access(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """Check that Cloud Run services do not allow unauthenticated invocations.

    A Cloud Run service is publicly invocable without any credentials when its
    IAM policy grants ``roles/run.invoker`` to ``allUsers`` or
    ``allAuthenticatedUsers``. Unless the service is intentionally public
    (e.g. a static site), this exposes it to SSRF, data exfiltration, and
    compute abuse.
    """
    try:
        services = _list_cloud_run_services(client, project_id, region)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-cloudrun-no-unauth-access",
                title=f"Unable to list Cloud Run services in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not services:
        return []

    run = client.service("run", "v2")
    offenders: list[dict[str, str]] = []

    for svc in services:
        svc_name = svc.get("name", "")
        try:
            policy = (
                run.projects()
                .locations()
                .services()
                .getIamPolicy(resource=svc_name)
                .execute()
            )
            for binding in policy.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    offenders.append(
                        {
                            "service": svc_name.split("/")[-1],
                            "role": binding.get("role", ""),
                        }
                    )
                    break
        except Exception:
            continue

    if not offenders:
        return [
            Finding(
                check_id="gcp-cloudrun-no-unauth-access",
                title=f"No Cloud Run services in {region} allow unauthenticated access",
                description=f"All {len(services)} Cloud Run service(s) in {region} require authentication.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                resource_id=f"projects/{project_id}/locations/{region}/services",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1", "CC6.6"],
                cis_gcp_controls=["1.2"],
            )
        ]

    return [
        Finding(
            check_id="gcp-cloudrun-no-unauth-access",
            title=f"{len(offenders)} Cloud Run service(s) in {region} allow unauthenticated invocation",
            description=(
                f"{len(offenders)} Cloud Run service(s) in {region} grant "
                "roles/run.invoker to allUsers or allAuthenticatedUsers. These services "
                "are callable from the public internet without any credentials."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Run::Service",
            resource_id=f"projects/{project_id}/locations/{region}/services",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove the allUsers IAM binding: "
                "`gcloud run services remove-iam-policy-binding SERVICE "
                "--region=REGION --member=allUsers --role=roles/run.invoker`. "
                "Enable Cloud IAP or require an OIDC token for service-to-service calls."
            ),
            soc2_controls=["CC6.1", "CC6.6"],
            cis_gcp_controls=["1.2"],
            iso27001_controls=["A.9.1.2"],
            details={"services_with_public_access": offenders[:20]},
        )
    ]


def check_cloud_run_no_default_service_account(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """Check that Cloud Run services do not use the default Compute Engine service account.

    The default Compute Engine SA (PROJECT_NUMBER-compute@developer.gserviceaccount.com)
    has the Editor role by default — far too broad for a Cloud Run service. Services
    should use a dedicated, narrowly scoped SA.
    """
    try:
        services = _list_cloud_run_services(client, project_id, region)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-cloudrun-no-default-sa",
                title=f"Unable to list Cloud Run services in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not services:
        return []

    offenders: list[dict[str, str]] = []
    for svc in services:
        template = svc.get("template", {})
        sa = template.get("serviceAccount", "")
        is_default_sa = not sa or bool(_DEFAULT_COMPUTE_SA_PATTERN.search(sa))
        if is_default_sa:
            offenders.append(
                {
                    "service": svc.get("name", "").split("/")[-1],
                    "service_account": sa or "(none — uses project default)",
                }
            )

    if not offenders:
        return [
            Finding(
                check_id="gcp-cloudrun-no-default-sa",
                title=f"All Cloud Run services in {region} use dedicated service accounts",
                description=f"No Cloud Run services in {region} use the default Compute Engine service account.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                resource_id=f"projects/{project_id}/locations/{region}/services",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.2"],
                cis_gcp_controls=["1.5"],
            )
        ]

    return [
        Finding(
            check_id="gcp-cloudrun-no-default-sa",
            title=f"{len(offenders)} Cloud Run service(s) in {region} use the default service account",
            description=(
                f"{len(offenders)} Cloud Run service(s) in {region} use the default "
                "Compute Engine service account, which carries the broad Editor role by default. "
                "A compromised service gains project-wide write access."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Run::Service",
            resource_id=f"projects/{project_id}/locations/{region}/services",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Create a dedicated SA with only the required roles and set it on the service: "
                "`gcloud run services update SERVICE --service-account=SA_EMAIL --region=REGION`."
            ),
            soc2_controls=["CC6.2"],
            cis_gcp_controls=["1.5"],
            iso27001_controls=["A.9.1.2", "A.8.2"],
            details={"services_using_default_sa": offenders[:20]},
        )
    ]


def check_cloud_run_ingress_restricted(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """Check that Cloud Run services restrict ingress to internal or load-balancer traffic.

    ``INGRESS_TRAFFIC_ALL`` (the default) allows the service to be reached by
    direct public URL without going through a load balancer, bypassing WAF,
    Cloud Armor, and CDN policies. Internal-only or load-balancer-only ingress
    forces all traffic through the controlled entry point.
    """
    try:
        services = _list_cloud_run_services(client, project_id, region)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-cloudrun-ingress-restricted",
                title=f"Unable to list Cloud Run services in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Run::Service",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not services:
        return []

    offenders: list[dict[str, str]] = []
    for svc in services:
        ingress = svc.get("ingress", "INGRESS_TRAFFIC_ALL")
        if ingress not in _RESTRICTED_INGRESS:
            offenders.append(
                {
                    "service": svc.get("name", "").split("/")[-1],
                    "ingress": ingress,
                }
            )

    if not offenders:
        return [
            Finding(
                check_id="gcp-cloudrun-ingress-restricted",
                title=f"All Cloud Run services in {region} restrict ingress traffic",
                description=f"All {len(services)} service(s) in {region} use internal or load-balancer-only ingress.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Run::Service",
                resource_id=f"projects/{project_id}/locations/{region}/services",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["3.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-cloudrun-ingress-restricted",
            title=f"{len(offenders)} Cloud Run service(s) in {region} accept all ingress traffic",
            description=(
                f"{len(offenders)} Cloud Run service(s) in {region} have "
                "INGRESS_TRAFFIC_ALL — they can be reached directly via the "
                "*.run.app URL, bypassing any Cloud Armor WAF or load balancer policy."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Run::Service",
            resource_id=f"projects/{project_id}/locations/{region}/services",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Restrict ingress: "
                "`gcloud run services update SERVICE --ingress=internal-and-cloud-load-balancing "
                "--region=REGION`. For internal microservices use `--ingress=internal`."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["3.1"],
            iso27001_controls=["A.13.1.1"],
            details={"services_with_open_ingress": offenders[:20]},
        )
    ]


def check_cloud_run_binary_authorization(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """Check that Cloud Run services have Binary Authorization enforced.

    Binary Authorization verifies the container image's provenance at deploy time,
    ensuring only trusted images built by your CI/CD pipeline can run. Without it,
    any container image (including attacker-substituted ones) can be deployed.
    """
    try:
        services = _list_cloud_run_services(client, project_id, region)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-cloudrun-binary-authorization",
                title=f"Unable to list Cloud Run services in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not services:
        return []

    missing_binauthz: list[str] = []
    for svc in services:
        binauthz = svc.get("binaryAuthorization", {})
        # useDefault=True means "use the project-level policy" — acceptable
        # policy=non-empty means a custom policy is set — acceptable
        use_default = binauthz.get("useDefault", False)
        policy = binauthz.get("policy", "")
        if not use_default and not policy:
            missing_binauthz.append(svc.get("name", "").split("/")[-1])

    if not missing_binauthz:
        return [
            Finding(
                check_id="gcp-cloudrun-binary-authorization",
                title=f"All Cloud Run services in {region} have Binary Authorization configured",
                description=f"All {len(services)} service(s) in {region} use Binary Authorization.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Run::Service",
                resource_id=f"projects/{project_id}/locations/{region}/services",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["5.7"],
            )
        ]

    return [
        Finding(
            check_id="gcp-cloudrun-binary-authorization",
            title=f"{len(missing_binauthz)} Cloud Run service(s) in {region} lack Binary Authorization",
            description=(
                f"{len(missing_binauthz)} Cloud Run service(s) in {region} do not have "
                "Binary Authorization enabled. Without it, any container image can be deployed "
                "without provenance verification, enabling supply-chain attacks."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Run::Service",
            resource_id=f"projects/{project_id}/locations/{region}/services",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable Binary Authorization: "
                "`gcloud run services update SERVICE --binary-authorization=default "
                "--region=REGION`. Set up a project policy that requires attestation "
                "from your CI/CD pipeline."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["5.7"],
            iso27001_controls=["A.12.5.1"],
            details={"services_without_binauthz": missing_binauthz[:20]},
        )
    ]


def check_cloud_run_no_plaintext_secrets(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """Check that Cloud Run services do not embed secrets in environment variables.

    Environment variables on Cloud Run services appear in plain text in the API
    response, the Cloud Console, and Cloud Audit Logs. Secrets (API keys, passwords,
    tokens) should be stored in Secret Manager and mounted as volumes or env vars
    via the secretKeyRef mechanism — not hardcoded in the service spec.
    """
    try:
        services = _list_cloud_run_services(client, project_id, region)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-cloudrun-no-plaintext-secrets",
                title=f"Unable to list Cloud Run services in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::Run::Service",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not services:
        return []

    suspicious: list[dict[str, str]] = []
    for svc in services:
        svc_short_name = svc.get("name", "").split("/")[-1]
        template = svc.get("template", {})
        containers = template.get("containers", [])
        for container in containers:
            for env in container.get("env", []):
                name = env.get("name", "")
                # Flag if the env var name suggests a secret AND it has a literal value
                # (not a secretKeyRef — those have "valueSource" instead of "value")
                has_literal_value = "value" in env and "valueSource" not in env
                if has_literal_value and _SECRET_PATTERNS.search(name):
                    suspicious.append(
                        {
                            "service": svc_short_name,
                            "env_var": name,
                        }
                    )
                    break

    if not suspicious:
        return [
            Finding(
                check_id="gcp-cloudrun-no-plaintext-secrets",
                title=f"No Cloud Run services in {region} have suspicious plaintext env vars",
                description=(
                    f"No Cloud Run services in {region} have environment variables "
                    "whose names suggest embedded secrets."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::Run::Service",
                resource_id=f"projects/{project_id}/locations/{region}/services",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.3"],
            )
        ]

    return [
        Finding(
            check_id="gcp-cloudrun-no-plaintext-secrets",
            title=f"{len(suspicious)} Cloud Run service(s) in {region} may embed secrets in env vars",
            description=(
                f"{len(suspicious)} Cloud Run service(s) in {region} have environment "
                "variables whose names suggest secrets (password, api_key, token, etc.) "
                "with literal string values rather than Secret Manager references. "
                "These values appear in plain text in the API response and audit logs."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::Run::Service",
            resource_id=f"projects/{project_id}/locations/{region}/services",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Store secrets in Secret Manager and reference them via secretKeyRef: "
                "`gcloud run services update SERVICE --update-secrets=ENV_VAR=SECRET_NAME:latest "
                "--region=REGION`. Remove the plaintext env var after migrating."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["5.3"],
            iso27001_controls=["A.10.1.1", "A.13.2.1"],
            details={"suspicious_env_vars": suspicious[:20]},
        )
    ]
