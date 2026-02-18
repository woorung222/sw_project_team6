#!/usr/bin/env bash
set -u

# =========================================================
# U_47 (상) 스팸 메일 릴레이 제한 | Ubuntu 24.04
# - 진단 기준 : SMTP 서버의 Open Relay 차단 설정 여부 점검
# - DB 정합성 : IS_AUTO=0
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_47"
CATEGORY="service"
IS_AUTO=0

U_47_1=0; U_47_2=0; U_47_3=0

# 1) Sendmail 점검
if command -v sendmail >/dev/null; then
    # promiscuous_relay 설정이 활성화되어 있으면 취약
    if [ -f "/etc/mail/sendmail.mc" ] && grep -v "^dnl" /etc/mail/sendmail.mc | grep -q "promiscuous_relay"; then
        U_47_1=1
    fi
fi

# 2) Postfix 점검
if command -v postconf >/dev/null; then
    # 릴레이 허용 네트워크 점검
    P_RELAY=$(postconf -n mynetworks 2>/dev/null)
    if [[ "$P_RELAY" == *"0.0.0.0/0"* ]] || [[ "$P_RELAY" == *"*"* ]]; then
        U_47_2=1
    fi
fi

# 3) Exim 점검
E_CONF="/etc/exim4/exim4.conf"
[ ! -f "$E_CONF" ] && E_CONF="/etc/exim/exim.conf"
if [ -f "$E_CONF" ]; then
    if grep -E "relay_from_hosts|hostlist relay" "$E_CONF" | grep -v "^#" | grep -q "*"; then
        U_47_3=1
    fi
fi

IS_VUL=0
[ "$U_47_1" -eq 1 ] || [ "$U_47_2" -eq 1 ] || [ "$U_47_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_47_1": $U_47_1, "U_47_2": $U_47_2, "U_47_3": $U_47_3 },
    "timestamp": "$DATE"
  }
}
EOF