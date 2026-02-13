#!/bin/bash

# [U-49] DNS 보안 버전 패치 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : DNS 서비스(named) 활성화 여부 및 보안 업데이트 필요 여부 점검
# DB 정합성 : IS_AUTO=0 (업데이트 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_49_1=0 # [Service] 활성화 상태
U_49_2=0 # [Version] 구버전 발견
IS_VUL=0
IS_AUTO=0 

# 1. [U_49_1] 서비스 활성화 확인
if systemctl is-active --quiet named 2>/dev/null; then
    U_49_1=1

    # 2. [U_49_2] 보안 패치 필요 여부 확인
    # dnf check-update가 100을 반환하면 업데이트 항목 존재
    dnf check-update bind -q >/dev/null 2>&1
    if [ $? -eq 100 ]; then
        U_49_2=1
    fi
fi

# 서비스가 켜져 있고 구버전(패치 대상)인 경우에만 실질적 취약으로 판단
[ "$U_49_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-49",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_49_1": $U_49_1, "U_49_2": $U_49_2 },
    "timestamp": "$DATE"
  }
}
EOF