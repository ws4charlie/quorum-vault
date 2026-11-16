# Spike: write-once storage for audit heads

Checked 2026-11-15/16. Status: **decided (human, 2026-11-16): local and CI use SeaweedFS pinned by digest; production targets AWS S3 Object Lock. MinIO is not used.**

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

## Decision and what was proven on SeaweedFS
- Local/CI store: `chrislusf/seaweedfs:4.53` pinned by the digest of its multi-arch index in `docker-compose.yml` (profile `archive`); the tests start their own container from that same line. Production: AWS S3 Object Lock. The archiver speaks plain S3, so any store with an Object Lock API and an independent compliance-mode assessment can replace it.
- `internal/auditchain/archive_s3_test.go` runs against the real store. In COMPLIANCE mode, during retention, **both the archiver's identity and the root identity are refused**: deleting the locked version (also with bypass-governance), shortening the retention, switching it to governance mode, deleting the bucket. A control test shows the same bypass **succeeds** in GOVERNANCE mode, so the refusals are the lock and not a broken test.
- What the store allows, and how the code deals with it: a plain write over an existing key adds a version, and a delete without a version id adds a delete marker. Neither touches the locked version. The archiver never writes a key twice (lookup, then a conditional `If-None-Match` write), and verification reads **every version** of every object and fails on content that does not belong under its key, so a marker or a forged newer version cannot hide or replace an archived head.
- SeaweedFS identities are coarse (Read, Write, List, Tagging, Admin; Write includes delete). The archiver needs `Admin` there only to read the bucket's lock configuration at start, so on SeaweedFS the lock, not the identity, is what stops deletes. On AWS the policy in the runbook denies delete, retention, lock and lifecycle changes outright.
- Each head is one object, keyed by source, count and hash, so a head republished unchanged every minute is one object. Verification lists and reads all of them; it is linear in the number of distinct heads.
- Not covered: SeaweedFS has no independent assessment we could find, so nothing here is a SEC 17a-4(f), FINRA 4511 or CFTC 1.31 claim. For one, the production store has to be an assessed one (S3 with Object Lock in COMPLIANCE mode, or an assessed appliance), and counsel has to read the assessment against QuorumVault's actual duties.
