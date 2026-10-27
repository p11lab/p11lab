#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/nss
control=/run/p11lab
params=$control/nss-lib-params
export NSS_LIB_PARAMS_FILE=$params
export P11LAB_MODULE=/usr/local/lib/p11lab/libsoftokn3.so

configure() {
    p11lab_writable_directory "$control"
    [ ! -L "$params" ] || p11lab_die "configuration cannot be a symlink"
    printf '%s\n' "configdir='sql:$owned' certPrefix='' keyPrefix='' secmod='' dbTokenDescription='P11Lab'" > "$control/params.$$"
    mv -f -- "$control/params.$$" "$params"
}
expected_marker() {
    printf '%s\n' 'schema=1' 'provider=nss' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'token=P11Lab' 'backend=sql'
}
complete() {
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] || p11lab_die "partial state: missing completion marker"
    [ "$(cat "$owned/complete")" = "$(expected_marker)" ] || p11lab_die "incompatible non-secret initialization configuration"
    for file in cert9.db key4.db pkcs11.txt; do
        [ ! -L "$owned/$file" ] || p11lab_die "partial or unsafe state"
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] || p11lab_die "partial state: missing token database file $file"
    done
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name nss -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name cert9.db ! -name key4.db ! -name pkcs11.txt -print -quit
    if listing=$(certutil -d "sql:$owned" -L 2>&1); then
        # This pinned stock utility opens the real certificate database; key
        # authentication stays with the application login, as with SoftHSM.
        db_listing=$listing
    else
        status=$?
        printf '%s\n' 'p11lab: native database health check failed' "$listing" >&2
        exit "$status"
    fi
}
init_token() {
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    p11lab_writable_directory "$state"
    configure
    if [ -e "$owned/complete" ]; then complete; exit 0; fi
    p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
    expected_marker > "$control/marker.$$"
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    # The SO credential is validated for interface uniformity with the
    # shared checker protocol; softoken has no SO role and never sees it.
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    unset P11LAB_PIN P11LAB_SO_PIN credential
    mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
    trap 'rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/init.$$" "$control/init-pw.$$"' EXIT HUP INT TERM
    mkdir -m 700 "$owned"
    printf '%s' "$user_credential" > "$control/init-pw.$$"
    unset user_credential
    # certutil -N on an existing database would silently change the key
    # password, so it runs only here, on a directory this init created.
    if certutil -d "sql:$owned" -N -f "$control/init-pw.$$" > "$control/init.$$" 2>&1; then
        rm -f -- "$control/init-pw.$$"
        cp -- "$control/marker.$$" "$owned/.complete.$$"
        mv -- "$owned/.complete.$$" "$owned/complete"
    else
        status=$?
        printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2
        cat -- "$control/init.$$" >&2
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
        [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        configure
        p11lab_check_find empty "partial state: refusing to reset volume with unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name nss -print -quit
        if [ -e "$owned" ]; then
            [ ! -L "$owned" ] || p11lab_die "refusing to reset unsafe state"
            rm -rf -- "$owned"
            printf '%s\n' "p11lab: reset removed $owned"
        else
            printf '%s\n' "p11lab: reset found no state at $owned"
        fi
        init_token
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        complete
        printf '%s\n' "$db_listing"
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        complete
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|reset|health|exec -- ARGV..." ;;
esac
