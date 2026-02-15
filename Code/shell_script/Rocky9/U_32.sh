#!/bin/bash

# [U-32] 홈 디렉터리로 지정한 디렉터리의 존재 관리 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/passwd에 설정된 홈 디렉터리가 실제로 존재하지 않는 경우 취약
# DB 정합성 : IS_AUTO=0 (계정 설정 변경 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_32_1=0 
IS_VUL=0
IS_AUTO=0 

# /etc/passwd 파일을 순회하며 점검
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    # 홈 디렉터리 경로가 설정되어 있는 경우만 점검
    if [ -n "$HOMEDIR" ]; then
        # 디렉터리가 실제로 존재하지 않으면 취약(-d 체크)
        if [ ! -d "$HOMEDIR" ]; then
            U_32_1=1
            break
        fi
    fi
done < /etc/passwd

IS_VUL=$U_32_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-32",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_32_1": $U_32_1 },
    "timestamp": "$DATE"
  }
}
EOF