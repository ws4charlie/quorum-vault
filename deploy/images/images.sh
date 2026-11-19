# Sourced by build.sh, smoke.sh and check-secrets.sh: the list of images and their zone. One place, so the three agree.
# name:zone:binaries (the binaries each image must contain; check-secrets.sh and smoke.sh use them)
QV_IMAGES="
qv-core:business:qv-core
qv-worker:business:qv-worker
qv-relay:business:qv-relay
qv-anchor-archiver:business:qv-anchor-archiver
qv-migrate:business:qv-migrate
qv-tools-business:business:qv-guardian,qv-sol-nonces
qv-gateway:signing:qv-gateway
qv-cosigner:signing:qv-cosigner
mpc-party:signing:mpc-party
qv-tools-signing:signing:qv-route,qv-fee-caps,qv-approvers,qv-btc-xpub
"
# development variants (SoftHSM2 added), signing zone only
QV_DEV_IMAGES="qv-gateway-dev:signing:qv-gateway qv-cosigner-dev:signing:qv-cosigner mpc-party-dev:signing:mpc-party"
QV_BUSINESS_BINS="qv-core qv-worker qv-relay qv-anchor-archiver qv-migrate qv-guardian qv-sol-nonces"
QV_SIGNING_BINS="qv-gateway qv-cosigner mpc-party qv-route qv-fee-caps qv-approvers qv-btc-xpub"
QV_IMAGE_PREFIX="${QV_IMAGE_PREFIX:-qv-image/}"
QV_IMAGE_TAG="${QV_IMAGE_TAG:-local}"
qv_all_images() { { printf '%s\n' $QV_IMAGES; printf '%s\n' $QV_DEV_IMAGES; } | grep .; }
