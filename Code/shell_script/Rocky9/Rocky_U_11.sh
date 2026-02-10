#!/bin/bash

# [U-11] 사용자 Shell 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 로그인이 필요하지 않은 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여된 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_11_1=0 
IS_VUL=0
VULN_ACCOUNTS=""

# --- 점검 시작 ---

# 점검할 시스템 계정 목록 (가이드 기준 + Rocky Linux 기본 시스템 계정 고려)
# 가이드: daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher
CHECK_LIST="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"

for acc in $CHECK_LIST; do
    # 1. /etc/passwd에 해당 계정이 있는지 확인
    ACC_INFO=$(grep "^$acc:" /etc/passwd)
    
    if [ ! -z "$ACC_INFO" ]; then
        # 2. 쉘(7번째 필드) 확인
        SHELL=$(echo "$ACC_INFO" | awk -F: '{print $7}')
        
        # 3. 쉘이 /bin/false 또는 /sbin/nologin 인지 확인
        # Rocky Linux에서는 주로 /sbin/nologin 사용
        if [[ "$SHELL" != "/bin/false" && "$SHELL" != "/sbin/nologin" && "$SHELL" != "/usr/sbin/nologin" ]]; then
            # 로그인 가능한 쉘을 가진 경우 취약
            U_11_1=1
            VULN_ACCOUNTS="$VULN_ACCOUNTS $acc($SHELL)"
        fi
    fi
done

# --- 최종 결과 집계 ---
IS_VUL=$U_11_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-11",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_11_1": $U_11_1
    },
    "timestamp": "$DATE"
  }
}
EOF