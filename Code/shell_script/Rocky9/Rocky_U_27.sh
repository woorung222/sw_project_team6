#!/bin/bash

# [U-27] R-commands 관련 파일(/etc/hosts.equiv, .rhosts) 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자 root 또는 해당계정, 권한 600 이하, '+' 설정 없을 것
# DB 정합성 : IS_AUTO=0 (서비스 영향 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_27_1=0 
IS_VUL=0
IS_AUTO=0 

# 1. /etc/hosts.equiv 점검
if [ -f "/etc/hosts.equiv" ]; then
    OWNER=$(stat -c "%U" "/etc/hosts.equiv")
    PERM=$(stat -c "%a" "/etc/hosts.equiv")
    PLUS_CHECK=$(grep -E "^\+" "/etc/hosts.equiv" 2>/dev/null)

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ] || [ -n "$PLUS_CHECK" ]; then
        U_27_1=1
    fi
fi

# 2. $HOME/.rhosts 점검 (모든 사용자)
if [ "$U_27_1" -eq 0 ]; then
    while IFS=: read -r user _ uid _ _ home _; do
        # UID 1000 이상(일반계정) 및 root(0) 점검
        if [[ "$uid" -ge 1000 || "$uid" -eq 0 ]] && [ -d "$home" ]; then
            RHOSTS="$home/.rhosts"
            if [ -f "$RHOSTS" ]; then
                f_owner=$(stat -c "%U" "$RHOSTS")
                f_perm=$(stat -c "%a" "$RHOSTS")
                f_plus=$(grep -E "^\+" "$RHOSTS" 2>/dev/null)
                
                if [[ "$f_owner" != "root" && "$f_owner" != "$user" ]] || [ "$f_perm" -gt 600 ] || [ -n "$f_plus" ]; then
                    U_27_1=1
                    break
                fi
            fi
        fi
    done < /etc/passwd
fi

IS_VUL=$U_27_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-27",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_27_1": $U_27_1 },
    "timestamp": "$DATE"
  }
}
EOF