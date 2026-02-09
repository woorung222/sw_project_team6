#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_52_1 : [inetd] Telnet 서비스 활성화 여부
# U_52_2 : [xinetd] Telnet 서비스 활성화 여부
# U_52_3 : [systemd] Telnet 서비스 활성화 여부
# U_52_4 : [Process] Telnet 관련 프로세스 실행 여부 
U_52_1=0
U_52_2=0
U_52_3=0
U_52_4=0

# --- 3. 점검 로직 수행 ---

# [1. inetd 점검]
if [ -f "/etc/inetd.conf" ]; then
    # 주석(#)이 아닌 라인에서 telnet 검색
    if grep -i "telnet" /etc/inetd.conf | grep -v "^#" > /dev/null; then
        U_52_1=1
    fi
fi

# [2. xinetd 점검]
if [ -f "/etc/xinetd.d/telnet" ]; then
    # disable = no 설정 확인
    if grep -i "disable" /etc/xinetd.d/telnet | grep -i "no" > /dev/null; then
        U_52_2=1
    fi
fi

# [3. systemd 점검]
# telnet.socket 유닛이 active 상태인지 확인
if systemctl list-units --type=socket 2>/dev/null | grep -i "telnet" | grep "active" > /dev/null; then
    U_52_3=1
fi

# [4. Process 점검] (요청하신 추가 항목)
# 현재 실행 중인 프로세스 중 telnet 관련 프로세스 확인 (grep 프로세스 제외)
if ps -ef | grep -v "grep" | grep -i "telnet" > /dev/null; then
    U_52_4=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_52_1" -eq 1 ] || [ "$U_52_2" -eq 1 ] || [ "$U_52_3" -eq 1 ] || [ "$U_52_4" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-52",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_52_1": $U_52_1,
      "U_52_2": $U_52_2,
      "U_52_3": $U_52_3,
      "U_52_4": $U_52_4
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
