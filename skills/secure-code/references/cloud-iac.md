# Cloud and infrastructure as code: AWS, GCP, Azure, Kubernetes, Terraform, Ansible

Review IaC files (`*.tf`, CloudFormation, Bicep, ARM, Pulumi, Kubernetes manifests, Helm charts, Ansible playbooks) and IAM policy documents. The code shows the intended state. The real account can differ: put that under "Cannot verify from code".

## Rules for every cloud

- Least privilege: no wildcard actions on wildcard resources. An application identity never has an owner or admin role.
- No long-lived keys for workloads → roles, managed identities, workload identity federation, OIDC from CI.
- Nothing is public by default: storage, databases, queues, snapshots, images, function endpoints.
- Encryption at rest and in transit is on for data stores.
- Secrets are in a secret manager. They are not in IaC variables with defaults, `*.tfvars` in git, instance user data, container environment in plain manifests, or outputs.
- Audit logs are on and stored where the workload cannot delete them **(ask)**.
- MFA for human accounts, and no daily use of the root or global admin account **(ask)**.

## AWS

- IAM policy with `"Action": "*"` or `"Resource": "*"` on write actions; `"Principal": "*"` or `{"AWS": "*"}` without a `Condition`.
- Privilege escalation rights: `iam:PassRole` on `*`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `iam:CreateAccessKey`, `sts:AssumeRole` on `*`.
- Role trust policy for another account or service without `sts:ExternalId`, `aws:SourceArn` or `aws:SourceAccount` (confused deputy).
- GitHub OIDC trust policy without a `sub` condition that names the repository and branch: every GitHub repository can assume the role.
- S3: public ACL or bucket policy, Block Public Access off, no encryption, long-lived presigned URLs.
- Security groups: `0.0.0.0/0` or `::/0` to SSH (22), RDP (3389), database ports or all ports.
- RDS: `publicly_accessible = true`, `storage_encrypted = false`, public snapshots, a master password in code.
- EC2: IMDSv1 allowed → `http_tokens = "required"` (SSRF then cannot read role credentials). Secrets in `user_data`.
- Lambda: secrets in plain environment variables; function URL with `AuthType = "NONE"`; one wide role for many functions.
- API Gateway routes without an authorizer. SNS, SQS, KMS and ECR policies with principal `*`.
- CloudTrail off or not multi-region.

## GCP

- IAM bindings for `allUsers` or `allAuthenticatedUsers` (buckets, Cloud Run invoker, Cloud Functions, BigQuery).
- Basic roles `roles/owner` and `roles/editor` for service accounts.
- User-managed service account keys (JSON files) → workload identity or attached service accounts.
- `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser` or `roles/iam.serviceAccountKeyAdmin` at project level (privilege escalation).
- The default Compute Engine service account with the `cloud-platform` scope.
- Firewall rules with source `0.0.0.0/0` to SSH, RDP or database ports.
- Cloud SQL with a public IP and `authorized_networks` of `0.0.0.0/0`; no `require_ssl`.
- Buckets without uniform bucket-level access. API keys without application and API restrictions.
- Firestore and Realtime Database rules that allow all reads or writes.

## Azure

- `Owner`, `Contributor` or `User Access Administrator` for an application at subscription or management-group scope.
- Service principal secrets with a long lifetime → managed identity or federated credentials.
- Storage: `allowBlobPublicAccess = true`, shared key access in code, SAS tokens with wide permissions (`sp=racwdl`), long expiry or no IP limit.
- Network security groups: source `*` or `Internet` to 22, 3389 or database ports.
- SQL firewall rule `0.0.0.0`–`255.255.255.255`; "Allow Azure services" on sensitive databases.
- Key Vault: wide access policies, purge protection off, public network access on.
- App Service and Functions: `httpsOnly = false`, old `minTlsVersion`, FTP on, `authLevel: anonymous` on functions that change data.

## Kubernetes and Helm

- RBAC: bindings to `cluster-admin`; rules with `verbs: ["*"]` or `resources: ["*"]`; `get`/`list` on `secrets`; `create` on `pods/exec`; the verbs `escalate`, `bind`, `impersonate`.
- `automountServiceAccountToken: false` for pods that do not call the API. No workloads on the `default` service account with extra rights.
- Pod security: `privileged: true`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` volumes, added capabilities, `allowPrivilegeEscalation: true`, root user. Set `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault`.
- Namespaces enforce Pod Security Admission level `restricted` or `baseline`.
- NetworkPolicy: a default-deny policy for each namespace, then explicit allows.
- Images are pinned by digest and come from a trusted registry.
- Secrets are not in manifests, Helm `values.yaml` or ConfigMaps in git → sealed secrets or an external secret store. Encryption of secrets in etcd is on **(ask)**.
- `Service` of type `LoadBalancer` or `NodePort` for an internal component. Ingress without TLS. The dashboard or the kubelet API exposed.
- CPU and memory limits are set.

## Terraform and other IaC

- State is in a remote backend with encryption, locking and narrow access. State contains secrets, also for values marked `sensitive = true`.
- Providers and modules are pinned (a version, or a git `ref` with a commit hash). `.terraform.lock.hcl` is committed.
- `local-exec` and `remote-exec` provisioners, and `external` data sources, with interpolated values → command injection.
- A module from an unknown source runs with your cloud credentials. Review it.
- `prevent_destroy` or deletion protection on data stores.
- CloudFormation: secret parameters use `NoEcho` and dynamic references to Secrets Manager. Pulumi: secrets are set with `--secret`.

## Ansible

- Secrets are in Ansible Vault or an external store, not in plain `vars`. Tasks that handle secrets set `no_log: true`.
- `shell:` and `command:` with `{{ variables }}` from outside → modules with arguments, or the `quote` filter.
- `validate_certs: no`, `get_url` over `http://` or without `checksum`.
- `become: true` only on the tasks that need it. Files with secrets get `mode: "0600"`.

## Serverless

- One role for each function, with only the rights that this function needs.
- Event data is untrusted input: object keys, queue messages, headers, webhook bodies.
- Timeouts, concurrency limits and budget alerts are set (denial of wallet).
