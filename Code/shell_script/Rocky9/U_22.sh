#!/bin/bash

# [U-22] /etc/services 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우 양호

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_22_1=0
IS_VUL=0
IS_AUTO=1 

TARGET_FILE="/etc/services"

if [ -f "$TARGET_FILE" ]; then
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 소유자 root, bin, sys 허용 / 권한 644 이하
    if [[ "$OWNER" =~ ^(root|bin|sys)$ ]] && [ "$PERM" -le 644 ]; then
        U_22_1=0
    else
        U_22_1=1
    fi
else
    # 파일이 없는 경우 (기본 파일이므로 취약 간주 가능하나 일반적으론 양호 처리)
    U_22_1=0
fi

IS_VUL=$U_22_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-22",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_22_1": $U_22_1 },
    "timestamp": "$DATE"
  }
}
EOF