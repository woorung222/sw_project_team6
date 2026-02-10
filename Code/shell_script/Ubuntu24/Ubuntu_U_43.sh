#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NIS 서비스(ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated) 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_43_1 : NIS 관련 프로세스 또는 서비스 유닛 활성화 여부 (통합)
U_43_1=0

# --- 3. 점검 로직 수행 ---

# [Check] NIS 관련 프로세스 및 서비스 유닛 확인
# ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated
NIS_PS=$(ps -ef | grep -iE "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep")
NIS_UNITS=$(systemctl list-unit-files 2>/dev/null | grep -iE "ypserv|ypbind|ypxfrd|yppasswdd|ypupdated|nis" | grep "enabled")

# 하나라도 발견되면 취약
if [ -n "$NIS_PS" ] || [ -n "$NIS_UNITS" ]; then
    U_43_1=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_43_1" -eq 1 ]; then
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
    "flag_id": "U-43",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_43_1": $U_43_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
