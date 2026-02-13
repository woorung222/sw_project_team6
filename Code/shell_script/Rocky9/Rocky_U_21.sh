#!/bin/bash

# [U-21] /etc/(r)syslog.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우 양호

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_21_1=0 # syslog.conf
U_21_2=0 # rsyslog.conf
IS_VUL=0
IS_AUTO=1 

# --- 함수 정의: 파일 권한 및 소유자 점검 ---
check_file_perm() {
    local FILE=$1
    if [ -f "$FILE" ]; then
        local OWNER=$(stat -c "%U" "$FILE")
        local PERM=$(stat -c "%a" "$FILE")
        # 소유자 root, bin, sys 허용 / 권한 640 이하
        if [[ "$OWNER" == "root" || "$OWNER" == "bin" || "$OWNER" == "sys" ]] && [ "$PERM" -le 640 ]; then
            echo 0
        else
            echo 1
        fi
    else
        echo 0 # 파일 없으면 해당 서비스 미사용으로 양호
    fi
}

U_21_1=$(check_file_perm "/etc/syslog.conf")
U_21_2=$(check_file_perm "/etc/rsyslog.conf")

[ "$U_21_1" -eq 1 ] || [ "$U_21_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-21",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_21_1": $U_21_1, "U_21_2": $U_21_2 },
    "timestamp": "$DATE"
  }
}
EOF