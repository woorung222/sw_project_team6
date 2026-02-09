#!/bin/bash

# [U-28] 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : TCP Wrapper, Iptables, Firewalld, UFW 중 하나라도 적절한 접근 제어가 설정되어 있으면 양호
# 주의: Rocky 9에서는 TCP Wrapper가 더 이상 기본 지원되지 않을 수 있으나, 가이드 기준에 따라 파일 점검 수행

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (1: 취약 / 설정 안됨으로 초기화)
U_28_1=1 # TCP Wrapper
U_28_2=1 # Iptables
U_28_3=1 # Firewalld
U_28_4=1 # UFW
IS_VUL=1 # 전체 취약 여부

# --- [U_28_1] TCP Wrapper 점검 ---
# /etc/hosts.deny에 ALL:ALL 설정이 있고, allow 파일이 존재하는지 확인
HOSTS_DENY="/etc/hosts.deny"
HOSTS_ALLOW="/etc/hosts.allow"

if [ -f "$HOSTS_DENY" ] && [ -f "$HOSTS_ALLOW" ]; then
    # hosts.deny에 주석 제외하고 ALL:ALL (대소문자 무시) 설정 확인
    DENY_CHECK=$(grep -i "ALL:ALL" "$HOSTS_DENY" | grep -v "^#")
    
    if [ ! -z "$DENY_CHECK" ]; then
        # deny가 설정되어 있다면 allow에 허용할 IP가 있는지 확인 (내용이 있는지)
        if [ -s "$HOSTS_ALLOW" ]; then
            U_28_1=0 # 양호
        fi
    fi
fi

# --- [U_28_2] Iptables 점검 ---
# iptables 명령어가 있고, 등록된 Rule이 있는지 확인
if command -v iptables > /dev/null 2>&1; then
    # Rule 라인 수 확인 (헤더 제외)
    IPTABLES_CNT=$(iptables -L -n | grep -v "^Chain" | grep -v "^target" | grep -v "^$" | wc -l)
    
    if [ "$IPTABLES_CNT" -gt 0 ]; then
        U_28_2=0 # 양호 (룰이 존재함)
    fi
fi

# --- [U_28_3] Firewalld 점검 (Rocky 9 기본) ---
# firewalld 서비스가 활성화(active) 상태인지 확인
if systemctl is-active --quiet firewalld; then
    # 실행 중이면 양호로 판단
    U_28_3=0
else
    U_28_3=1
fi

# --- [U_28_4] UFW 점검 ---
# ufw 명령어가 있고, status가 active인지 확인
if command -v ufw > /dev/null 2>&1; then
    UFW_STATUS=$(ufw status | grep -i "Status: active")
    if [ ! -z "$UFW_STATUS" ]; then
        U_28_4=0 # 양호
    fi
else
    # 설치되어 있지 않으면 취약(사용 안 함)으로 처리
    U_28_4=1
fi

# --- 전체 결과 집계 ---
# 4가지 보안 도구 중 하나라도 안전(0)하게 설정되어 동작 중이면 
# 시스템은 외부 접속 통제를 하고 있다고 판단하여 IS_VUL = 0 (양호)
if [ $U_28_1 -eq 0 ] || [ $U_28_2 -eq 0 ] || [ $U_28_3 -eq 0 ] || [ $U_28_4 -eq 0 ]; then
    IS_VUL=0
else
    IS_VUL=1
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
    "flag_id": "U-28",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_28_1": $U_28_1,
      "U_28_2": $U_28_2,
      "U_28_3": $U_28_3,
      "U_28_4": $U_28_4
    },
    "timestamp": "$DATE"
  }
}
EOF