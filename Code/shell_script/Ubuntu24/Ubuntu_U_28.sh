#!/usr/bin/env bash
set -u

# =========================================================
# U_28 (상) 접속 IP 및 포트 제한 | Ubuntu 24.04
# - 진단 기준: TCP Wrapper, Iptables, Firewalld, UFW 중 하나라도 활성화 여부
# - DB 정합성: IS_AUTO=0 (관리자 접속 차단 위험으로 수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_28"
CATEGORY="file"
IS_AUTO=0

U_28_1=1; U_28_2=1; U_28_3=1; U_28_4=1

# 1) [U_28_1] TCP Wrapper 점검
if [ -f "/etc/hosts.deny" ] && grep -vE '^#|^\s#' /etc/hosts.deny | grep -iwq "ALL: ALL"; then
    U_28_1=0
fi

# 2) [U_28_2] Iptables 점검
if command -v iptables >/dev/null 2>&1; then
    if iptables -nL INPUT 2>/dev/null | grep -vE "^Chain|^target|^$" | grep -q .; then
        U_28_2=0
    fi
fi

# 3) [U_28_3] Firewalld 점검
if systemctl is-active --quiet firewalld 2>/dev/null; then
    U_28_3=0
fi

# 4) [U_28_4] UFW 점검
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -iq "Status: active"; then
        U_28_4=0
    fi
fi

# 하나라도 방화벽이 작동 중이면 양호
IS_VUL=1
if [ "$U_28_1" -eq 0 ] || [ "$U_28_2" -eq 0 ] || [ "$U_28_3" -eq 0 ] || [ "$U_28_4" -eq 0 ]; then
    IS_VUL=0
fi

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_28_1": $U_28_1, "U_28_2": $U_28_2, "U_28_3": $U_28_3, "U_28_4": $U_28_4 },
    "timestamp": "$DATE"
  }
}
EOF