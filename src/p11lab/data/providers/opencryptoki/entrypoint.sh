#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/opencryptoki
data=$owned/lib/opencryptoki
token=$data/swtok
control=/run/p11lab/opencryptoki
tool=/usr/local/bin/p11lab-opencryptoki
export P11LAB_MODULE=/usr/local/lib/p11lab/libopencryptoki.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL

configure() {
    [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -eq 1001 ] || p11lab_die "SWToken requires a non-root UID and primary GID 1001"
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    # These controls can redirect native state, tracing, libraries or identities.
    # They are not supported recipe inputs; do not silently overwrite them.
    for name in PKCS_APP_STORE PKCS11_SHMEM_FILE OPENCRYPTOKI_TRACE_LEVEL OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "unsupported native override: $name"
    done
    p11lab_writable_directory /run/p11lab
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    p11lab_check_find empty "unsafe control files" "$control" -mindepth 1 -maxdepth 1 ! \( -type f -o -type d -o -type s \) -print -quit
    for directory in locks logs; do
        p11lab_writable_directory "$control/$directory"
        [ "$(stat -c %u "$control/$directory")" = "$(id -u)" ] && [ "$(stat -c %g "$control/$directory")" = 1001 ] || p11lab_die "control directory ownership mismatch"
    done
    p11lab_check_find empty "unsafe daemon logs" "$control/logs" -mindepth 1 ! \( -type f -name pkcsslotd.log \) -print -quit
    p11lab_check_find empty "unsafe native lock entries" "$control/locks" -mindepth 1 -maxdepth 1 ! \( -type d -name swtok -o -type f -name LCK..APIlock \) -print -quit
    if [ -e "$control/locks/swtok" ]; then
        p11lab_writable_directory "$control/locks/swtok"
        [ "$(stat -c %u "$control/locks/swtok")" = "$(id -u)" ] && [ "$(stat -c %g "$control/locks/swtok")" = 1001 ] || p11lab_die "native lock directory ownership mismatch"
        p11lab_check_find empty "unsafe native lock files" "$control/locks/swtok" -mindepth 1 ! \( -type f -name LCK..swtok \) -print -quit
    fi
    p11lab_check_find empty "ephemeral file ownership or hardlink mismatch" "$control/locks" "$control/logs" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
    printf 'p11lab:x:%s:1001:P11Lab:/var/lib/p11lab:/bin/sh\n' "$(id -u)" > "$control/passwd.$$"
    printf 'p11lab:x:1001:p11lab\n' > "$control/group.$$"
    mv -f -- "$control/passwd.$$" "$control/passwd"
    mv -f -- "$control/group.$$" "$control/group"
    export NSS_WRAPPER_PASSWD=$control/passwd NSS_WRAPPER_GROUP=$control/group
    export LD_PRELOAD=/usr/local/lib/p11lab/libnss_wrapper.so
    printf '%s\n' 'version opencryptoki-3.27' 'slot 0' '{' '    stdll = /usr/local/lib/p11lab/libpkcs11_sw.so' '    tokversion = 3.12' '}' > "$control/config.$$"
    mv -f -- "$control/config.$$" "$control/expected-config"
    printf '%s\n' 'schema=1' 'provider=opencryptoki' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" 'slot=0' 'backend=SWToken' 'tokversion=3.12' 'group=1001' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] || p11lab_die "partial or unsafe owned state"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name opencryptoki -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name opencryptoki.conf ! -name strength.conf ! -name lease ! -name lib -print -quit
    [ -L "$owned/strength.conf" ] && [ "$(readlink "$owned/strength.conf")" = /usr/share/p11lab/opencryptoki/strength.conf ] || p11lab_die "incompatible protected strength configuration"
    for directory in "$owned" "$owned/lib" "$data" "$token" "$token/TOK_OBJ" "$data/HSM_MK_CHANGE"; do
        [ ! -L "$directory" ] && [ -d "$directory" ] && [ -w "$directory" ] && [ -x "$directory" ] || p11lab_die "partial or unsafe token directory"
        [ "$(stat -c %u "$directory")" = "$(id -u)" ] && [ "$(stat -c %g "$directory")" = 1001 ] || p11lab_die "token directory ownership mismatch"
    done
    p11lab_check_find empty "unknown token directories" "$owned/lib" -mindepth 1 -maxdepth 1 ! -name opencryptoki -print -quit
    p11lab_check_find empty "unknown token directories" "$data" -mindepth 1 -maxdepth 1 ! -name swtok ! -name HSM_MK_CHANGE -print -quit
    p11lab_check_find empty "unexpected SWToken hardware state" "$data/HSM_MK_CHANGE" -mindepth 1 -print -quit
    p11lab_check_find empty "unsafe token files" "$token" -mindepth 1 -maxdepth 1 ! \( -type f \( -name NVTOK.DAT -o -name MK_SO -o -name MK_USER \) -o -type d -name TOK_OBJ \) -print -quit
    # Native object creation uses mkstemp("OBXXXXXX"), including mixed case.
    p11lab_check_find empty "unsafe object files" "$token/TOK_OBJ" -regextype posix-extended -mindepth 1 -maxdepth 1 ! \( -type f \( -name OBJ.IDX -o -regex '.*/OB[A-Za-z0-9]{6}' \) \) -print -quit
    p11lab_check_find empty "object file ownership or hardlink mismatch" "$token/TOK_OBJ" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
    for file in "$owned/complete" "$owned/opencryptoki.conf" "$owned/lease" "$token/NVTOK.DAT" "$token/MK_SO" "$token/MK_USER"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "provisioned file ownership or hardlink mismatch"
    done
    [ "$(stat -c %s "$token/NVTOK.DAT")" = 592 ] && [ "$(stat -c %s "$token/MK_SO")" = 40 ] && [ "$(stat -c %s "$token/MK_USER")" = 40 ] || p11lab_die "partial state: invalid native token file sizes"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    cmp -s -- "$control/expected-config" "$owned/opencryptoki.conf" || p11lab_die "incompatible non-secret initialization configuration"
}

init_token() {
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    p11lab_writable_directory "$state"
    configure
    if [ -e "$owned/complete" ]; then validate_static; exec "$tool" health; fi
    p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    so_credential=$credential
    [ "${#user_credential}" -ge 4 ] && [ "${#user_credential}" -le 8 ] && [ "${#so_credential}" -ge 4 ] && [ "${#so_credential}" -le 8 ] || p11lab_die "native SWToken PIN bounds are 4..8 bytes"
    [ "$so_credential" != 87654321 ] || p11lab_die "SO credential must replace the native factory credential"
    unset P11LAB_PIN P11LAB_SO_PIN credential
    mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
    trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT
    init_locked
}

init_locked() {
        mkdir -m 700 "$owned"
        # A caller volume may inherit a setgid parent. Native token/lock files
        # must belong to the declared PKCS#11 group, not that parent group.
        chgrp 1001 "$owned"
        chmod g-s "$owned"
        # Native SWToken expects its empty object directory before the first
        # module open. No initialized token bytes are installed here.
        mkdir -p "$data/HSM_MK_CHANGE" "$token/TOK_OBJ"
        cp -- "$control/expected-config" "$owned/opencryptoki.conf"
        ln -s /usr/share/p11lab/opencryptoki/strength.conf "$owned/strength.conf"
        : > "$owned/lease"
        # Explicitly seal this adapter-owned lock file: inherited default ACLs
        # can give shell redirection a group mask despite the process umask.
        chmod 600 "$owned/lease"
        # The bounded stdin record has one separator LF; each secret is single
        # line. The supervisor reads and erases it before launching children.
        # Forward container signals to that supervisor and wait for cleanup.
        printf '%s\n%s' "$user_credential" "$so_credential" | "$tool" init &
        worker=$!
        unset user_credential so_credential
        trap 'kill -TERM "$worker" 2>/dev/null || :; wait "$worker" || :; exit 143' TERM
        trap 'kill -INT "$worker" 2>/dev/null || :; wait "$worker" || :; exit 130' INT
        trap 'kill -HUP "$worker" 2>/dev/null || :; wait "$worker" || :; exit 129' HUP
        if wait "$worker"; then
            cp -- "$control/expected-marker" "$owned/.complete.$$"
            mv -- "$owned/.complete.$$" "$owned/complete"
        else
            status=$?
            printf '%s\n' 'p11lab: native initialization failed; partial state retained' >&2
            exit "$status"
        fi
}
case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat /usr/share/p11lab/provider.json
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        init_token
        ;;
    reset)
        [ "$#" -eq 1 ] || p11lab_die "reset takes no arguments"
        p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
        p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        p11lab_writable_directory "$state"
        configure
        [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        [ "${#user_credential}" -ge 4 ] && [ "${#user_credential}" -le 8 ] && [ "${#so_credential}" -ge 4 ] && [ "${#so_credential}" -le 8 ] || p11lab_die "native SWToken PIN bounds are 4..8 bytes"
        [ "$so_credential" != 87654321 ] || p11lab_die "SO credential must replace the native factory credential"
        unset user_credential so_credential credential
        if [ -e "$owned" ]; then
            [ ! -L "$owned" ] || p11lab_die "refusing to reset unsafe state"
            rm -rf -- "$owned"
            printf '%s\n' "p11lab: reset removed $owned"
        else
            printf '%s\n' "p11lab: reset found no state at $owned"
        fi
        if [ -n "$(find "$control/locks" -mindepth 1 -print -quit 2>/dev/null)" ]; then
            rm -rf -- "$control/locks"
            printf '%s\n' "p11lab: reset cleared $control/locks"
        fi
        # configure() exports the NSS wrapper for its caller; drop it so the
        # re-init below validates pristine inputs like a fresh invocation.
        unset LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP
        init_token
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        validate_static
        exec "$tool" health
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        validate_static
        exec "$tool" exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|reset|health|exec -- ARGV..." ;;
esac
