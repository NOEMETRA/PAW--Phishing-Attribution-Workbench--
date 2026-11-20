#!/usr/bin/env bash
# Run with the absolute path to the Python of an installed PAW wheel and a new output directory.
set -euo pipefail
python="$(realpath -s "${1:?installed virtualenv Python required}")"
out="$(realpath -m "${2:?new output directory required}")"
fixture="$(realpath "$(dirname "$0")/sentinel_private_link_fixture.py")"
bundle="$("$python" -I -c 'import certifi; print(certifi.where())')"
mkdir -m 700 "$out"
# Every interface, route, firewall rule and bind mount below lives in new namespaces.
unshare --user --map-root-user --mount --propagation private --net --pid --fork --mount-proc \
    bash -se -- "$python" "$out" "$fixture" "$bundle" <<'NAMESPACE'
set -euo pipefail
python="$1"; out="$2"; fixture="$3"; bundle="$4"
cd "$out"
export PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH PYTHONHOME PAW_DATA_DIR
test "$(ip -o link show | wc -l)" -eq 1
unshare --net sleep infinity &
peer=$!
trap 'kill "$peer" 2>/dev/null || true' EXIT
for _ in {1..100}; do
    if [[ "$(readlink /proc/self/ns/net)" != "$(readlink "/proc/$peer/ns/net")" ]]; then break; fi
    sleep .02
done
test "$(readlink /proc/self/ns/net)" != "$(readlink "/proc/$peer/ns/net")"
remote=(nsenter -t "$peer" -n)
ip link add client0 type veth peer name fixture0
ip link set fixture0 netns "$peer"
ip addr add 192.0.2.1/30 dev client0
ip link set client0 up
ip link set lo up
"${remote[@]}" ip addr add 192.0.2.2/30 dev fixture0
"${remote[@]}" ip link set fixture0 up
"${remote[@]}" ip link set lo up
"${remote[@]}" sysctl -qw net.ipv4.ip_unprivileged_port_start=53
test -z "$(ip route show default)"
test -z "$("${remote[@]}" ip route show default)"
{ readlink /proc/self/ns/net; ip -br addr; ip route; "${remote[@]}" readlink /proc/self/ns/net; "${remote[@]}" ip -br addr; "${remote[@]}" ip route; } > topology.log

printf 'nameserver 192.0.2.2\noptions timeout:1 attempts:1\n' > resolver
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > nsswitch
printf '127.0.0.1 localhost\n192.0.2.2 fixture-peer.test\n' > hosts
mount --bind hosts /etc/hosts
mount --bind resolver /etc/resolv.conf
mount --bind nsswitch /etc/nsswitch.conf
# A private trust anchor makes TLS exercise normal hostname and chain verification.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=sentinel.test' \
    -addext 'subjectAltName=DNS:sentinel.test' -keyout fixture.key -out fixture.pem 2> cert.log
trap 'kill "$peer" 2>/dev/null || true; unlink fixture.key' EXIT
mount --bind fixture.pem "$bundle"
unpriv=(setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs --)
"${remote[@]}" "${unpriv[@]}" "$python" -I "$fixture" serve >server.log 2>&1 &
server=$!
for _ in {1..100}; do
    [[ -f ready ]] && break
    kill -0 "$server"
    sleep .05
done
test -f ready
"${unpriv[@]}" "$python" -I "$fixture" observe
nft add table inet paw_fixture
nft 'add chain inet paw_fixture output { type filter hook output priority 0; policy accept; }'
nft add rule inet paw_fixture output ip daddr 192.0.2.2 tcp dport 8443 counter reject
"${unpriv[@]}" "$python" -I "$fixture" denied
nft list chain inet paw_fixture output > denial.log
grep -Eq 'counter packets [1-9][0-9]* ' denial.log
nft delete table inet paw_fixture
"${unpriv[@]}" "$python" -I "$fixture" restored
"${unpriv[@]}" "$python" -I "$fixture" foreground initial
nft add table inet paw_foreground
nft 'add chain inet paw_foreground output { type filter hook output priority 0; policy accept; }'
nft add rule inet paw_foreground output ip daddr 192.0.2.2 tcp dport 8080 counter reject
"${unpriv[@]}" "$python" -I "$fixture" foreground blocked
nft list chain inet paw_foreground output > foreground-denial.log
grep -Eq 'counter packets [1-9][0-9]* ' foreground-denial.log
nft delete table inet paw_foreground
"${unpriv[@]}" "$python" -I "$fixture" foreground restored
kill "$server"
wait "$server" || test "$?" -eq 143
NAMESPACE
