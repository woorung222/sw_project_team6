#!/bin/bash

# [U-19] /etc/hosts 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root이고, 권한이 600 이하인 경우 양호 (DB 기준 반영)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_19_1=0 
IS_VUL=0
IS_AUTO=1 

TARGET_FILE="/etc/hosts"

if [ -f "$TARGET_FILE" ]; then
    # 소유자 및 권한 확인
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 진단 로직: 소유자 root && 권한 600 이하 (DB 기준 600 적용)
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 600 ]; then
        U_19_1=0
    else
        U_19_1=1
    fi
else
    # 파일이 없으면 보안상 취약으로 간주
    U_19_1=1
fi

IS_VUL=$U_19_1

# JSON 출력
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-19",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_19_1": $U_19_1 },
    "timestamp": "$DATE"
  }
}
EOF