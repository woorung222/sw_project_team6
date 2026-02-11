#!/bin/bash

# [U-27] R-commands 서비스 관련 파일(/etc/hosts.equiv, .rhosts) 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/hosts.equiv 및 $HOME/.rhosts 파일의 소유자가 root 또는 해당 계정이고, 권한이 600 이하이며, '+' 설정이 없으면 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_27_1=0 # 0: 양호, 1: 취약
IS_VUL=0

# --- 점검 시작 ---

# 1. /etc/hosts.equiv 점검
HOSTS_EQUIV="/etc/hosts.equiv"

if [ -f "$HOSTS_EQUIV" ]; then
    OWNER=$(stat -c "%U" "$HOSTS_EQUIV")
    PERM=$(stat -c "%a" "$HOSTS_EQUIV")
    PLUS_CHECK=$(grep -E "^\+" "$HOSTS_EQUIV") # '+' 설정 확인

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ] || [ -n "$PLUS_CHECK" ]; then
        U_27_1=1
    fi
fi

# 2. $HOME/.rhosts 점검 (root 및 일반 사용자)
# /etc/passwd에서 사용자 홈 디렉터리 추출
while IFS=: read -r user _ uid _ _ home _; do
    if [[ "$uid" -ge 1000 || "$uid" -eq 0 ]]; then
        RHOSTS="$home/.rhosts"
        
        if [ -f "$RHOSTS" ]; then
             f_owner=$(stat -c "%U" "$RHOSTS")
             f_perm=$(stat -c "%a" "$RHOSTS")
             f_plus=$(grep -E "^\+" "$RHOSTS")
             
             # 소유자가 root도 아니고 해당 사용자도 아니면 취약
             # 또는 권한이 600 초과이거나 '+' 설정이 있으면 취약
             if [[ "$f_owner" != "root" && "$f_owner" != "$user" ]] || \
                [[ "$f_perm" -gt 600 ]] || \
                [[ -n "$f_plus" ]]; then
                 U_27_1=1
             fi
        fi
    fi
done < /etc/passwd

# --- 전체 결과 집계 ---
if [ $U_27_1 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-27",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_27_1": $U_27_1
    },
    "timestamp": "$DATE"
  }
}
EOF