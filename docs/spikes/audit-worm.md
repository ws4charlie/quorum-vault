# Spike: write-once storage for audit heads

Checked 2026-11-15. Status: **MinIO is not usable as the default; the choice of store is open (see "Decision needed").**

## MinIO today
- The `minio/minio` repository is archived (read-only since 2026-04-25). Its README says it is no longer maintained, ships source only, and points to the commercial AIStor. Source licence: AGPLv3. [github.com/minio/minio](https://github.com/minio/minio)
- No official image of the community edition: the Docker Hub repository `minio/minio` is gone (Docker Hub API answers "object not found" on 2026-11-15; `docker manifest inspect minio/minio:latest` is denied). Reports say old images may remain on quay.io; `quay.io/minio/minio:latest` has no manifest and the tag API needs a login, so nothing there can be pinned by digest from here. [MinIO stops distributing free Docker images](https://news.ycombinator.com/item?id=45665452), [StableBuild](https://www.stablebuild.com/blog/minio-images-disappeared-from-docker-hub)
- So "a pinned official image, pinned by digest" cannot be met. Building our own from archived AGPL source means owning an unmaintained storage server in the evidence path.

## Independent assessment (SEC 17a-4(f), FINRA 4511(c), CFTC 1.31(c)-(d))
- Cohasset Associates assessed MinIO Object Storage: [MinIO page](https://www.min.io/cohasset/introduction), [report PDF, 2020-08-10](https://www.MinIO.io/resources/docs/MinIO-Object-Storage-Assessment-Report-2020-08-10.pdf). Vendor-commissioned.
- It covers one old release (RELEASE 172), on-premises, Object Lock enabled **at bucket creation**, default mode **COMPLIANCE** (governance mode does not qualify), qualified hardware. Gateway mode and public cloud are out of scope. It is Cohasset's professional opinion, not an endorsement.
- It says nothing about the archived community edition we could still build. I did not check for a newer report; none of the alternatives below turned up one.
- This task does not make QuorumVault "17a-4 compliant". 17a-4(f) also needs an audit-trail or duplicate copy, indexing, a designated third party or undertakings, and retention of the records themselves; QuorumVault is not a broker-dealer record system. Heads are evidence aids, not the regulated records.

## Alternatives with Object Lock (COMPLIANCE)
| Store | Object Lock compliance | Licence / image | Independent assessment found |
|---|---|---|---|
| AWS S3 | Yes, the reference implementation; Cohasset-assessed ([AWS](https://aws.amazon.com/s3/features/object-lock/)) | managed | yes (AWS) |
| SeaweedFS | Yes, per its docs ([deepwiki](https://deepwiki.com/seaweedfs/seaweedfs/7.1-object-locking-and-worm)); the filer is a separate path that needs its own guard ([note](https://tekromancy.com/blog/immutable-backups-s3-object-lock-seaweedfs-kopia-restic/)) | Apache-2.0; `chrislusf/seaweedfs` on Docker Hub, active (release 4.53, 2026-11-08) | none found |
| Ceph RGW | Yes, no user incl. admin can delete or shorten in compliance mode ([Ceph](https://ceph.io/en/news/blog/2025/rgw-deep-dive-3/)) | LGPL; heavy to run locally | none found |
| RustFS | Claimed; young (1.0 reported 2026-09); distributed mode "under testing" | Apache-2.0; `rustfs/rustfs` on Docker Hub | none found |

Local test use of any of these proves our code against an S3 Object Lock API, not a regulatory claim. "Root cannot delete" holds only at the S3 API; whoever has the disks or the host can still destroy data, so a real deployment uses S3 itself or an assessed appliance, and keeps the store under a different administrator than the Kafka brokers and the signing zones.

## What this does not give
It shows that a head existed and was not altered after it was archived. It does not show the chain is complete: a chain that was cut or rewritten before its next head was archived is not detected, and a head archived while the chain was already wrong is kept as it was.

## Decision needed (lead)
1. Local/CI store: **SeaweedFS (recommended)**, pinned by digest, because it is Apache-2.0, has an official maintained image and implements COMPLIANCE lock. Other choices: Ceph (heavy), RustFS (young), or a self-built MinIO from archived source (not recommended).
2. Production target: the archiver speaks plain S3 (Object Lock API), so production can be AWS S3 or any assessed store. Say which, so the runbook and the retention default name it.
