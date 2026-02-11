#!/bin/bash

# [U-21] /etc/(r)syslog.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_21_1=0 # syslog.conf
U_21_2=0 # rsyslog.conf
IS_VUL=0

# --- 함수 정의: 파일 권한 및 소유자 점검 ---
check_file_perm() {
    local FILE=$1
    
    if [ -f "$FILE" ]; then
        local OWNER=$(stat -c "%U" "$FILE")
        local PERM=$(stat -c "%a" "$FILE")
        
        # 1. 소유자 체크 (root, bin, sys 중 하나면 OK)
        if [[ "$OWNER" == "root" || "$OWNER" == "bin" || "$OWNER" == "sys" ]]; then
            # 2. 권한 체크 (640 이하인지 확인)
            if [ "$PERM" -le 640 ]; then
                echo 0 # 양호
            else
                echo 1 # 권한 취약 (예: 644)
            fi
        else
            echo 1 # 소유자 취약
        fi
    else
        echo 0 # 파일이 없으면 양호 (해당 서비스 미사용으로 간주)
    fi
}

# --- [U_21_1] syslog.conf 점검 ---
U_21_1=$(check_file_perm "/etc/syslog.conf")

# --- [U_21_2] rsyslog.conf 점검 (Rocky 9 Main) ---
U_21_2=$(check_file_perm "/etc/rsyslog.conf")


# --- 전체 결과 집계 ---
if [ $U_21_1 -eq 1 ] || [ $U_21_2 -eq 1 ]; then
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
    "flag_id": "U-21",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_21_1": $U_21_1,
      "U_21_2": $U_21_2
    },
    "timestamp": "$DATE"
  }
}
EOF