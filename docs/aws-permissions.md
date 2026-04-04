# AWS Permissions

This toolkit is designed to run read-only against AWS accounts.

## Starting point

Use [infra/transilience-compliance-scanning-policy.json](../infra/transilience-compliance-scanning-policy.json) as a baseline policy document for scanning access.

## Principles

- prefer read-only IAM actions
- scope credentials to the account or environment you are assessing
- keep write privileges out of the scanning role
- review the policy against the modules you actually use

## Notes

- Some workflows rely on service-specific discovery APIs across IAM, EC2, S3, CloudTrail, GuardDuty, Config, Inspector, Lambda, ECS, and related services.
- Optional integrations like GitHub, Slack, and Jira require their own credentials and are not part of AWS IAM policy scope.
- Remediation output is generated as Terraform and instructions only; no AWS mutation should be required for normal scans.

