#!/usr/bin/env bash
# Run with an installed PAW wheel's Python, a new output directory and optional family (ipv4 or ipv6).
set -euo pipefail
python="$(realpath -s "${1:?installed virtualenv Python required}")"
out="$(realpath -m "${2:?new output directory required}")"
fixture="$(realpath "$(dirname "$0")/sentinel_private_link_fixture.py")"
bundle="$("$python" -I -c 'import certifi; print(certifi.where())')"
family="${3:-ipv4}"
case "$family" in
    ipv4) client_ip=192.0.2.1; peer_ip=192.0.2.2; prefix=30; nft_family=ip; address_options=() ;;
    ipv6) client_ip=2001:db8:14::1; peer_ip=2001:db8:14::2; prefix=64; nft_family=ip6; address_options=(nodad) ;;
    *) echo 'Address family must be ipv4 or ipv6' >&2; exit 2 ;;
esac
mkdir -m 700 "$out"
# Every interface, route, firewall rule and bind mount below lives in new namespaces.
unshare --user --map-root-user --mount --propagation private --net --pid --fork --mount-proc \
    bash -se -- "$python" "$out" "$fixture" "$bundle" "$client_ip" "$peer_ip" "$prefix" "$nft_family" "${address_options[@]}" <<'NAMESPACE'
set -euo pipefail
python="$1"; out="$2"; fixture="$3"; bundle="$4"
export PAW_FIXTURE_CLIENT_IP="$5" PAW_FIXTURE_PEER_IP="$6"
prefix="$7"; nft_family="$8"
shift 8
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
ip addr add "$PAW_FIXTURE_CLIENT_IP/$prefix" dev client0 "$@"
ip link set client0 up
ip link set lo up
"${remote[@]}" ip addr add "$PAW_FIXTURE_PEER_IP/$prefix" dev fixture0 "$@"
"${remote[@]}" ip link set fixture0 up
"${remote[@]}" ip link set lo up
"${remote[@]}" sysctl -qw net.ipv4.ip_unprivileged_port_start=53
test -z "$(ip route show default)"
test -z "$("${remote[@]}" ip route show default)"
test -z "$(ip -6 route show default)"
test -z "$("${remote[@]}" ip -6 route show default)"
{ readlink /proc/self/ns/net; ip -br addr; ip route; ip -6 route; "${remote[@]}" readlink /proc/self/ns/net; "${remote[@]}" ip -br addr; "${remote[@]}" ip route; "${remote[@]}" ip -6 route; } > topology.log

printf 'nameserver %s\noptions timeout:1 attempts:1\n' "$PAW_FIXTURE_PEER_IP" > resolver
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > nsswitch
printf '127.0.0.1 localhost\n%s fixture-peer.test\n' "$PAW_FIXTURE_PEER_IP" > hosts
mount --bind hosts /etc/hosts
mount --bind resolver /etc/resolv.conf
mount --bind nsswitch /etc/nsswitch.conf
# A private trust anchor makes TLS exercise normal hostname and chain verification.
cert_names=DNS:sentinel.test
foreground_port=8080
if [[ "$nft_family" == ip6 ]]; then
    cert_names+=",IP:$PAW_FIXTURE_PEER_IP"
    foreground_port=8443
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=sentinel.test' \
    -addext "subjectAltName=$cert_names" -keyout fixture.key -out fixture.pem 2> cert.log
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
nft add rule inet paw_fixture output "$nft_family" daddr "$PAW_FIXTURE_PEER_IP" tcp dport 8443 counter reject
"${unpriv[@]}" "$python" -I "$fixture" denied
nft list chain inet paw_fixture output > denial.log
grep -Eq 'counter packets [1-9][0-9]* ' denial.log
nft delete table inet paw_fixture
"${unpriv[@]}" "$python" -I "$fixture" restored
if [[ "$nft_family" == ip6 ]]; then
    umount "$bundle"
fi
"${unpriv[@]}" "$python" -I "$fixture" foreground initial
nft add table inet paw_foreground
nft 'add chain inet paw_foreground output { type filter hook output priority 0; policy accept; }'
nft add rule inet paw_foreground output "$nft_family" daddr "$PAW_FIXTURE_PEER_IP" tcp dport "$foreground_port" counter reject
"${unpriv[@]}" "$python" -I "$fixture" foreground blocked
nft list chain inet paw_foreground output > foreground-denial.log
grep -Eq 'counter packets [1-9][0-9]* ' foreground-denial.log
nft delete table inet paw_foreground
"${unpriv[@]}" "$python" -I "$fixture" foreground restored
"${unpriv[@]}" "$python" -I "$fixture" foreground unchanged
kill "$server"
wait "$server" || test "$?" -eq 143
NAMESPACE
