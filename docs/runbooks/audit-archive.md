# Runbook: the audit-head archive

Every audit chain publishes its head to Kafka (`qv.audit.heads`). `qv-anchor-archiver` copies each head into a write-once S3 bucket, so the
heads outlive the topic. This runbook sets the bucket up, runs the archiver, verifies from it, and answers its alerts. Design and limits:
[audit.md](../audit.md), [spike note](../spikes/audit-worm.md).

## What the archive gives, and what it does not

| It gives | It does not give |
|---|---|
| Each published head is stored once, and cannot be deleted, overwritten or have its retention shortened until the retention ends, by anyone | A proof that the chain is complete: a chain cut or rewritten before its next head was archived is not seen |
| Verification that still works if the topic is gone | A regulatory claim by itself (see the spike note: SEC 17a-4(f) needs an assessed store and more than this) |
| A refusal to start on a bucket that does not promise the above | Protection from whoever controls the store's disks or host. Keep the store under another administrator than the brokers and the signing zones |

## Set up the bucket (once, per environment)

Object Lock can only be switched on **when the bucket is created**. The retention in COMPLIANCE mode **cannot be undone by anyone, the account
owner included**: objects stored in a test bucket stay (and are billed) until the retention ends. Never point a test at a production account
with a long retention.

1. Create the bucket with Object Lock enabled. It is versioned automatically.
2. Set the default retention: mode COMPLIANCE, at least what the archiver is told (`-retention`, default 7 years = 2555 days).
3. Create the archiver's identity with only the policy below. Its keys go to the archiver as `QV_ARCHIVE_ACCESS_KEY` and
   `QV_ARCHIVE_SECRET_KEY`, or as files named by `QV_ARCHIVE_ACCESS_KEY_FILE` and `QV_ARCHIVE_SECRET_KEY_FILE`. Never in the repo or a flag.

AWS S3 (production target; any store with an Object Lock API and an independent compliance-mode assessment works the same way):

```bash
aws s3api create-bucket --bucket qv-audit-heads --object-lock-enabled-for-bucket --region eu-central-1 \
  --create-bucket-configuration LocationConstraint=eu-central-1
aws s3api put-object-lock-configuration --bucket qv-audit-heads --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":2555}}}'
```

The archiver's policy: read and put, and an explicit deny for everything that could delete, shorten or reconfigure.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions",
       "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"],
     "Resource": ["arn:aws:s3:::qv-audit-heads", "arn:aws:s3:::qv-audit-heads/heads/*"]},
    {"Effect": "Deny", "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention",
       "s3:PutObjectLegalHold", "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning",
       "s3:DeleteBucket", "s3:PutBucketPolicy"],
     "Resource": ["arn:aws:s3:::qv-audit-heads", "arn:aws:s3:::qv-audit-heads/*"]}
  ]
}
```

The archiver sends no retention of its own: the bucket's default applies to each object, and it checks at start that the default is
COMPLIANCE and long enough. Verification needs the same read permissions and no write.

Local development and CI use SeaweedFS, pinned by digest in `docker-compose.yml` (profile `archive`). Its identities are coarse (Read, Write,
List, Admin): the archiver's needs `Admin` to read the lock configuration, so on SeaweedFS the lock, and not the identity, is what stops
deletes; the tests prove that. Set the four `QV_ARCHIVE_*` key variables to random values, then:

```bash
docker compose --profile archive up -d --wait seaweedfs
# create the bucket with the root identity (any S3 client), e.g. with aws-cli against http://127.0.0.1:18333, then put-object-lock-configuration as above
```

## Run the archiver

It runs outside the signing zones: it holds the archive's keys and reads Kafka, and no zone waits for it.

```bash
qv-anchor-archiver -brokers kafka:9092 -archive-bucket qv-audit-heads -archive-region eu-central-1 -retention 61320h -metrics-listen 127.0.0.1:9103
# other stores: -archive-endpoint https://s3.example.internal (path-style addressing is then on)
```

- It refuses to start, with the reason, if the bucket has no Object Lock, no default retention, a default in GOVERNANCE mode or one shorter than `-retention`. Fix the bucket (a new bucket if the lock was off at creation), not the flag.
- Its offset is committed only after the head is stored. Restarting it, or running a second one, stores nothing twice: the object key is the head itself (source, count, hash).
- Several instances in one consumer group are safe. A new consumer group replays the whole topic and stores only what is missing.
- Metrics and alerts: `monitoring/audit-archive.rules.yml`.

## Verify from the archive

The verify commands of `qv-relay`, `qv-gateway` and `qv-cosigner` take the archive next to, or instead of, a dump of the topic. The chain must contain every
archived head and contradict none.

```bash
qv-relay verify -dsn "$DATABASE_URL" -archive-bucket qv-audit-heads -archive-region eu-central-1
# add -anchors dump.jsonl to check both; the output says how many heads came from each
```

It reads every version of every object, so a delete marker over a head does not hide it, and an object whose content does not belong under its
key is an error. A warning line at the top means the bucket is not write-once: do not treat the result as evidence.

## Alerts

| Alert | Meaning | What to do |
|---|---|---|
| `QVAuditArchiveLagging` | heads wait on the topic and nothing was archived for 10 minutes | read the archiver's log: credentials expired, store unreachable, or the store refusing. Heads are not lost: Kafka keeps them until its retention. Act well before that |
| `QVAuditArchiveStoreErrors` | the store refused or was unreachable, repeatedly | same; the archiver retries the same head until it is stored |
| `QVAuditArchiveSourceSilent` | no head of one source for 15 minutes | the chain's publisher, Kafka or the archiver stopped; check which |
| `QVAuditArchiveBadRecords` | something on the topic is not a head | someone can write to the topic who should not. Find the record; it was skipped |
| `QVAuditArchiveMetricsMissing` | the archiver is down or not scraped | start it; it catches up from its committed offset |

If the retention ever has to be longer, create a new bucket with the longer default and start another archiver on it; the old objects stay
under their old retention. A shorter retention is not possible, by design.
