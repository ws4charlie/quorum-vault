# The HSM PIN of the gateway

`qv-gateway` logs in to its HSM token with a PIN that it reads **once, at start, from a file**: set `QV_HSM_PIN_FILE` to the path. The file holds the PIN and nothing else (a trailing newline is dropped). Its mode must have no world bit and no group write or execute bit: 0400 and 0600 are fine, and 0440 or 0640 are accepted (the log names the mode) so that a Kubernetes Secret volume with `fsGroup` works. A symlinked Secret layout is judged by the file it points at. This is the same rule as the party's `pin_file`.

A PIN in the environment (`QV_HSM_PIN`) is refused at start unless `QV_ENV` is `dev` or `test`; the error names `QV_HSM_PIN_FILE`. Setting both is an error. A zone with only MPC signers needs no PIN. The PIN is never written to a log line, an error, the health output or the metrics.

Offline tools run by a person (`qv-cold`, `qv-rekey`) read the PIN from an environment variable of the person's shell (`qv-cold` takes the variable's name, not the PIN: `-pin-env`, `pin_env`; `qv-rekey` reads `QV_HSM_PIN`); none takes the PIN as a command-line argument, which any user of the machine could read in the process list. On Kubernetes, put the PIN in a Secret of the signing cluster, mount it as a file (`defaultMode` 0440, the pod's `fsGroup` as group) and point `QV_HSM_PIN_FILE` at it.
