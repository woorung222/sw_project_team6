#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : Finger 서비스 비활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
U_34_1=0 # inetd
U_34_2=0 # xinetd
U_34_3=0 # systemd/process

# --- 3. 점검 로직 수행 ---

# [Check 1] inetd 설정 확인 (U_34_1)
if [ -f "/etc/inetd.conf" ]; then
    INETD_CHECK=$(grep -v "^#" /etc/inetd.conf | grep "finger")
    if [ -n "$INETD_CHECK" ]; then
        U_34_1=1
    fi
fi

# [Check 2] xinetd 설정 확인 (U_34_2)
if [ -f "/etc/xinetd.d/finger" ]; then
    if ! grep -q "disable[[:space:]]*=[[:space:]]*yes" /etc/xinetd.d/finger; then
        U_34_2=1
    fi
fi

# [Check 3] Systemd 서비스 및 프로세스, 포트 확인 (U_34_3)
FINGER_PROC=$(ps -ef | grep -E "fingerd|cfingerd|efingerd" | grep -v "grep")
FINGER_PORT=$(sudo netstat -antp 2>/dev/null | grep ":79 " | grep "LISTEN")

if [ -n "$FINGER_PROC" ] || [ -n "$FINGER_PORT" ]; then
    U_34_3=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_34_1" -eq 1 ] || [ "$U_34_2" -eq 1 ] || [ "$U_34_3" -eq 1 ]; then
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
    "flag_id": "U-34",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_34_1": $U_34_1,
      "U_34_2": $U_34_2,
      "U_34_3": $U_34_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
