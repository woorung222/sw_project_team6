#!/usr/bin/env bash
set -u

# =========================================================
# U_51 (중) DNS 서비스의 취약한 동적 업데이트 설정 금지 | Ubuntu 24.04
# - 진단 기준 : allow-update 설정에 any(전체 허용) 존재 여부 점검
# - DB 정합성 : IS_AUTO=0
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_51"
CATEGORY="service"
IS_AUTO=0

U_51_1=0

# DNS 설정 파일 탐색 (Ubuntu 표준 경로)
NAMED_CONF="/etc/bind/named.conf.options"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/named.conf"

if [ -f "$NAMED_CONF" ]; then
    # allow-update 설정 확인 (주석 제외)
    ALLOW_UPDATE=$(grep -r "allow-update" "$NAMED_CONF" 2>/dev/null | grep -v "^#")
    
    # 설정이 존재하고 'any'를 포함하면 취약
    if [ -n "$ALLOW_UPDATE" ] && echo "$ALLOW_UPDATE" | grep -qi "any"; then
        U_51_1=1
    fi
fi

IS_VUL=$U_51_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_51_1": $U_51_1 },
    "timestamp": "$DATE"
  }
}
EOF