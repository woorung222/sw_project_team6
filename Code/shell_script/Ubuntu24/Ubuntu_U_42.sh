#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 가이드에 명시된 불필요한 RPC 서비스 15종 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_42_1 : [1. inetd] 내 RPC 서비스 설정 여부
# U_42_2 : [2. xinetd] 내 RPC 서비스 설정 여부
# U_42_3 : [3. systemd] 및 rpcinfo 기반 서비스 활성 여부
U_42_1=0
U_42_2=0
U_42_3=0

# 가이드 명시 불필요 RPC 서비스 리스트 (15종)
RPC_LIST="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

# --- 3. 점검 로직 수행 ---

# [Step 1] 1. inetd 설정 확인
if [ -f "/etc/inetd.conf" ]; then
    INETD_RPC=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$RPC_LIST")
    if [ -n "$INETD_RPC" ]; then
        U_42_1=1
    fi
fi

# [Step 2] 2. xinetd 설정 확인
if [ -d "/etc/xinetd.d" ]; then
    # disable = no 로 설정된 항목 중 RPC 리스트에 포함되는 것 확인
    XINETD_RPC=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$RPC_LIST")
    if [ -n "$XINETD_RPC" ]; then
        U_42_2=1
    fi
fi

# [Step 3] 3. systemd 및 실시간 서비스 확인
# systemd 유닛 상태 확인 (enabled 된 것)
SYSTEMD_RPC=$(systemctl list-unit-files 2>/dev/null | grep -iE "$RPC_LIST" | grep "enabled")

# rpcinfo -p 결과 확인 (실제 포트 리스닝 중인 것)
RPCINFO_RPC=""
if command -v rpcinfo > /dev/null; then
    RPCINFO_RPC=$(rpcinfo -p 2>/dev/null | grep -iE "$RPC_LIST")
fi

if [ -n "$SYSTEMD_RPC" ] || [ -n "$RPCINFO_RPC" ]; then
    U_42_3=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_42_1" -eq 1 ] || [ "$U_42_2" -eq 1 ] || [ "$U_42_3" -eq 1 ]; then
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
    "flag_id": "U-42",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_42_1": $U_42_1,
      "U_42_2": $U_42_2,
      "U_42_3": $U_42_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
