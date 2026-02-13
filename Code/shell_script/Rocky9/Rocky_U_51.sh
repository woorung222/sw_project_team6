#!/bin/bash

# [U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : DNS 서비스 활성화 시 allow-update 설정이 any(전체 허용)인 경우 취약
# DB 정합성 : IS_AUTO=0 (업데이트 장애 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_51_1=0 
IS_VUL=0
IS_AUTO=0 

# 1. DNS 서비스 활성화 여부 확인
if systemctl is-active --quiet named 2>/dev/null; then
    NAMED_CONF="/etc/named.conf"
    if [ -f "$NAMED_CONF" ]; then
        # 주석 제외하고 allow-update 설정 확인
        ALLOW_UPDATE=$(grep -vE "^#|^\/\/" "$NAMED_CONF" 2>/dev/null | grep "allow-update")
        if [ -n "$ALLOW_UPDATE" ] && echo "$ALLOW_UPDATE" | grep -q "any"; then
            U_51_1=1
        fi
    fi
fi

IS_VUL=$U_51_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-51",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_51_1": $U_51_1 },
    "timestamp": "$DATE"
  }
}
EOF