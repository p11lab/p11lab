#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# p11scope demo, privileged container phase. Runs as root inside the demo
# vessel: BPF uprobe attach needs CAP_SYS_ADMIN on this kernel, so the
# container runs privileged with the host PID namespace. Reads only mounted
# inputs, writes only $WORK (chowned to the caller at the end). The
# disposable token PINs never reach retained logs; the script greps for
# them before reporting success.
set -eu

: "${WORK:?container work directory required}"
: "${P11SCOPE_DIR:?mounted p11scope bundle directory required}"
: "${HOST_UID:?caller uid required}"
: "${HOST_GID:?caller gid required}"
: "${DEMO_LIB:?mounted lib.sh required}"

# shellcheck source=lib.sh
. "$DEMO_LIB"

if [ "$(id -u)" != "0" ]; then
    echo "refused: privileged phase needs uid 0 for BPF attach" >&2
    exit 1
fi

P11SCOPE=$P11SCOPE_DIR/p11scope
MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
TOOL=/usr/bin/pkcs11-tool
CHILD_USER=obs-child
CHILD_UID=10001
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")
: "${SCRATCH:?mktemp failed to create scratch}"
chown "$CHILD_UID:$CHILD_UID" "$SCRATCH"
chmod 700 "$SCRATCH"
# Ordering invariant: SCRATCH is always set where this trap is installed (set -u enforced).
trap 'rm -rf "$SCRATCH"' EXIT
TOKENDIR="$SCRATCH/tokens"
CONF="$SCRATCH/softhsm.conf"
PROFILE="$SCRATCH/observed-profile.json"

log() {
    printf '%s\n' "$*"
}

log "== versions =="
grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release | tee "$WORK/os-release.txt"
dpkg -l softhsm2 opensc openssl python3 2>/dev/null | grep '^ii' | tee "$WORK/dpkg-versions.txt"
uname -r | tee "$WORK/kernel.txt"
"$P11SCOPE" --version | tee "$WORK/p11scope-version.txt"
test -f "$MODULE" || { echo "missing observed module: $MODULE" >&2; chown -R "$HOST_UID:$HOST_GID" "$WORK"; exit 1; }

log "== kernel filesystems =="
mountpoint -q /sys/kernel/debug 2>/dev/null || mount -t debugfs debugfs /sys/kernel/debug 2>>"$WORK/mounts.txt" || true
mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf 2>>"$WORK/mounts.txt" || true
{
    mountpoint -q /sys/kernel/debug && echo "debugfs: mounted" || echo "debugfs: MISSING"
    mountpoint -q /sys/fs/bpf && echo "bpffs: mounted" || echo "bpffs: MISSING"
} | tee -a "$WORK/mounts.txt"

log "== disposable observed token (owned by $CHILD_USER) =="
mkdir -p "$TOKENDIR"
chown "$CHILD_UID:$CHILD_UID" "$TOKENDIR"
chmod 700 "$TOKENDIR"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\nslots.mechanisms = ALL\n' "$TOKENDIR" >"$CONF"
chown "$CHILD_UID:$CHILD_UID" "$CONF"
chmod 600 "$CONF"
PIN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
SOPIN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
# shellcheck disable=SC2016 # $1/$2/$3 expand in the su'd shell, not here.
su "$CHILD_USER" -s /bin/sh -c 'SOFTHSM2_CONF=$1 softhsm2-util --init-token --free --label ObsDemo --pin "$2" --so-pin "$3"' sh "$CONF" "$PIN" "$SOPIN" >"$WORK/token-init.txt" 2>&1

log "== privileged preflight =="
set +e
timeout 120 "$P11SCOPE" doctor >"$WORK/doctor-privileged.txt" 2>&1
DOCTOR_RC=$?
set -e
printf 'doctor_rc=%s\n' "$DOCTOR_RC" | tee "$WORK/doctor-privileged-rc.txt"
TIER=$(grep -E '^capability tier:' "$WORK/doctor-privileged.txt" || true)
printf '%s\n' "$TIER" | tee "$WORK/tier-privileged.txt"
case "$TIER" in
    *'T0 offline'*)
        cat >"$WORK/unsupported.txt" <<'EOF'
Live capture is unavailable on this host: privileged preflight reports
T0 offline. Reproduce with: p11scope doctor (exit status and FAIL rows
in doctor-privileged.txt). Tracing stays optional: ordinary image
consumers never need it.
EOF
        finalize_result "$WORK/RESULT" "P11SCOPE_DEMO_UNSUPPORTED" \
            "$WORK" "$HOST_UID" "$HOST_GID"
        log "P11SCOPE_DEMO_UNSUPPORTED (T0, evidence retained)"
        exit 0
        ;;
esac

log "== own-process capture of a PKCS#11 slot/mechanism listing =="
export SUDO_UID=$CHILD_UID SUDO_GID=$CHILD_UID
set +e
timeout 300 "$P11SCOPE" run --module "$MODULE" --pause auto \
    -o "$PROFILE" -- \
    /usr/bin/env SOFTHSM2_CONF="$CONF" "$TOOL" --module "$MODULE" -L -M >"$WORK/run-transcript.txt" 2>&1
RUN_RC=$?
set -e
printf 'run_rc=%s\n' "$RUN_RC" | tee "$WORK/run-rc.txt"
[ "$RUN_RC" = "0" ] || { echo "capture failed, see run-transcript.txt" >&2; chown -R "$HOST_UID:$HOST_GID" "$WORK"; exit 1; }
cp "$PROFILE" "$WORK/observed-profile.json"
python3 - "$WORK/observed-profile.json" >"$WORK/capture-summary.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
evidence = doc['evidence']
called = [f for f in doc['functions'] if f['calls'] > 0]
print(json.dumps({
    'schema': doc['schema'],
    'completeness': evidence['completeness'],
    'verdict_detail': evidence['verdict_detail'],
    'event_loss': evidence['event_loss'],
    'attached_probes': evidence['attached_probes'],
    'attach_mechanisms': evidence['attach_mechanisms'],
    'slots': evidence['slots'],
    'semantic_unverified_slots': evidence['semantic_unverified_slots'],
    'functions_called': len(called),
    'total_calls': sum(f['calls'] for f in called),
    'capture_scope': doc['capture']['scope'],
    'capture_mode': doc['capture']['mode'],
    'capture_kernel': doc['capture']['kernel'],
    'pid_namespace': evidence['pid_namespace'],
}, indent=2, sort_keys=True))
EOF
cat "$WORK/capture-summary.json"

log "== credential-leak self-check =="
if grep -q "$PIN" "$WORK/token-init.txt" "$WORK/run-transcript.txt" 2>/dev/null; then
    echo "user PIN leaked into retained logs" >&2
    chown -R "$HOST_UID:$HOST_GID" "$WORK"
    exit 1
fi
if grep -q "$SOPIN" "$WORK/token-init.txt" "$WORK/run-transcript.txt" 2>/dev/null; then
    echo "SO PIN leaked into retained logs" >&2
    chown -R "$HOST_UID:$HOST_GID" "$WORK"
    exit 1
fi
unset PIN SOPIN
finalize_result "$WORK/RESULT" "P11SCOPE_DEMO_OK" \
    "$WORK" "$HOST_UID" "$HOST_GID"
log "P11SCOPE_DEMO_OK"
