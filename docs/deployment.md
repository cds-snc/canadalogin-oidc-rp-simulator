# Deployment

The central CanadaLogin release pipeline v1.2.4 builds
`simple-rp-simulator/Dockerfile` once in dev and deploys the image by digest to
dev, test and staging. The multi-RP sample is not the deployed application.

Apply the simulator release infrastructure and configure the GitHub environment
variables before merging this workflow. The infrastructure rollout and variable
values are documented in `gc-signin-terraform/docs/simulator-release-pipeline.md`.
Both destination repositories must exist before enabling dev ECR replication.

Dev follows main. Release-please updates `.deployed_versions/test.json` when a
release is made. Promote staging by changing `.deployed_versions/staging.json`
to a released version through a reviewed PR. Configure a main branch ruleset
requiring reviews for these files; this repository did not previously have
deployment CODEOWNERS.

## Initial release

This repository had no release tags. The initial `1.0.0` manifest and version
files are a versioning baseline, not a statement of the previously deployed
version. On the first main push, the pipeline supports a newly introduced
manifest version by resolving it to the workflow commit until its tag exists.
This initial push builds and deploys that commit to dev, test and staging.

After release-please creates the first tagged release, promote staging to that
tagged version. Until then, do not manually deploy test/staging or use the
force-redeploy option: manual deployments require a real release tag. No release
tags are created by this workflow migration.

## Manual deployments

Run **Release pipeline** on main. Select an environment (or `all`). Select
**rebuild** when the desired tagged image is missing, including an older release
that predates the new artifact repository. ECR replication is asynchronous;
confirm the desired image exists in the target account before deploying.
**force-redeploy** targets every enabled environment, regardless of the selected
environment.