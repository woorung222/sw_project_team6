#!/bin/bash

# [U-31] 홈 디렉터리 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 홈 디렉터리 소유자가 해당 계정이고, 타 사용자(Other) 쓰기 권한이 없는 경우 양호

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_31_1=0 
IS_VUL=0
IS_AUTO=1 

# /etc/passwd 파일을 라인별로 읽어 전수 점검
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    # 1. 홈 디렉터리가 실제로 존재하지 않으면 건너뜀
    if [ ! -d "$HOMEDIR" ]; then continue; fi

    # 2. 시스템 중요 디렉터리는 제외 (오탐 방지)
    if [[ "$HOMEDIR" =~ ^(/|/bin|/sbin|/dev|/proc|/sys)$ ]]; then continue; fi

    # 3. 소유자 및 권한 확인
    OWNER=$(stat -c "%U" "$HOMEDIR")
    PERM_STR=$(stat -c "%A" "$HOMEDIR")

    # [진단] 소유자가 해당 계정이 아니거나, Other에게 쓰기(w) 권한이 있으면 취약
    if [ "$OWNER" != "$USERNAME" ] || [ "${PERM_STR:8:1}" == "w" ]; then
        U_31_1=1
        break
    fi
done < /etc/passwd

IS_VUL=$U_31_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-31",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_31_1": $U_31_1 },
    "timestamp": "$DATE"
  }
}
EOF