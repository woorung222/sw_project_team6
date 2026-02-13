#!/usr/bin/env bash
set -u

# =========================================================
# U_49 (상) DNS 보안 버전 패치 | Ubuntu 24.04
# - 진단 기준 : BIND9 서비스 활성화 여부 및 최신 패치 적용 상태 점검
# - DB 정합성 : IS_AUTO=0 (업데이트 위험으로 수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_49"
CATEGORY="service"
IS_AUTO=0

U_49_1=0; U_49_2=0

# 1) [U_49_1] DNS(BIND9) 서비스 활성화 점검
# Ubuntu에서는 서비스명이 bind9인 경우가 많음
if systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then
    U_49_1=1

    # 2) [U_49_2] 구버전(보안 업데이트 대상) 점검
    if apt list --upgradable 2>/dev/null | grep -qiE "bind9|named"; then
        U_49_2=1
    fi
fi

IS_VUL=0
[ "$U_49_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_49_1": $U_49_1, "U_49_2": $U_49_2 },
    "timestamp": "$DATE"
  }
}
EOF