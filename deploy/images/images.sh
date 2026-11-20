# Sourced by build.sh, smoke.sh and check-secrets.sh: the list of images and their zone. One place, so the three agree.
# name:zone:binaries (the binaries each image must contain; check-secrets.sh and smoke.sh use them)
QV_IMAGES="
qv-core:business:qv-core
qv-worker:business:qv-worker
qv-relay:business:qv-relay
qv-anchor-archiver:business:qv-anchor-archiver
qv-migrate:business:qv-migrate
qv-approval-web:business:qv-approval-web
qv-tools-business:business:qv-guardian,qv-sol-nonces
qv-gateway:signing:qv-gateway
qv-cosigner:signing:qv-cosigner
mpc-party:signing:mpc-party
qv-attest-broker:signing:qv-attest-broker
qv-tools-signing:signing:qv-route,qv-fee-caps,qv-approvers,qv-btc-xpub,qv-keysets,qv-party-admin,qv-migrate
"
# development variants (SoftHSM2 added), signing zone only
QV_DEV_IMAGES="qv-gateway-dev:signing:qv-gateway qv-cosigner-dev:signing:qv-cosigner mpc-party-dev:signing:mpc-party qv-attest-broker-dev:signing:qv-attest-broker"
# tee-sim variants (SIMULATED enclave): dev base + the teesim build. Deliberately NOT in QV_IMAGES or QV_DEV_IMAGES (so build.sh, smoke.sh and check-secrets.sh leave them alone): build by name.
QV_TEESIM_IMAGES="mpc-party-teesim qv-attest-broker-teesim"
QV_BUSINESS_BINS="qv-core qv-worker qv-relay qv-anchor-archiver qv-migrate qv-approval-web qv-guardian qv-sol-nonces"
QV_SIGNING_BINS="qv-gateway qv-cosigner mpc-party qv-attest-broker qv-route qv-fee-caps qv-approvers qv-btc-xpub qv-keysets qv-party-admin"
QV_IMAGE_PREFIX="${QV_IMAGE_PREFIX:-qv-image/}"
QV_IMAGE_TAG="${QV_IMAGE_TAG:-local}"
# The release set: the production images only. The -dev variants (SoftHSM2) are never published, under any name: publish.sh, release-gate.sh and
# ci/helm (TestReleaseSetHasNoDev) refuse a -dev or tee-sim name here. qv_all_images (below) is for local builds and checks.
qv_release_images() { printf '%s\n' $QV_IMAGES | grep .; }
qv_all_images() { { printf '%s\n' $QV_IMAGES; printf '%s\n' $QV_DEV_IMAGES; } | grep .; }
# The one business binary a signing image may hold: qv-migrate is a schema tool run as a Job in each signing cluster (-zone signing); the business
# migrations embedded in it are public SQL and give no access. image:binary pairs.
QV_ZONE_ALLOW="qv-tools-signing:qv-migrate"
