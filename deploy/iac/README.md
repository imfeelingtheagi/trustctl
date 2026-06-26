# trstctl IaC and GitOps examples

This folder contains copyable integration examples for teams that manage trstctl
resources from infrastructure pipelines:

- `gitops/base/` is a Kustomize bundle that runs Terraform with the
  `terraform-provider-trstctl` provider to create a profile, issue a short-lived
  PKI secret, and store an application secret.
- `gitops/argocd/application.yaml` points ArgoCD at that base.
- `gitops/flux/kustomization.yaml` points Flux at the same base.
- `pulumi/trstctl-resources/` is a Pulumi TypeScript dynamic-provider example
  that provisions the same resources through the served REST API.
- `gitlab/trstctl-iac.gitlab-ci.yml` is a GitLab CI template for plan/apply.

All examples expect `TRSTCTL_ENDPOINT` and `TRSTCTL_TOKEN` from your CI or
cluster Secret. Mutations use idempotency keys so retries do not create
duplicate resources.
