#!/bin/bash

# [U-28] 접속 IP 및 포트 제한
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-28"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_28_1=0; U_28_2=0; U_28_3=0; U_28_4=0; IS_VUL=0

# 1. [U_28_1] /etc/hosts.deny, hosts.allow 점검
if [[ -f "/etc/hosts.deny" ]]; then
    DENY_CHECK=$(run_cmd "[U_28_1] hosts.deny 'ALL:ALL' 설정 확인" "grep -vE '^#|^\s#' /etc/hosts.deny | grep -i 'ALL:ALL' || echo 'missing'")
    if [[ "$DENY_CHECK" == "missing" ]]; then
        U_28_1=1
        log_basis "[U_28_1] /etc/hosts.deny 파일에 'ALL:ALL' 거부 설정이 없음" "취약"
    else
        # hosts.allow 확인 (ALL:ALL 허용이 있으면 안 됨, 원래 로직상 allow에 ALL:ALL 있으면 양호로 본 로직이 있었으나 가이드라인은 제한 여부임. 원본 로직 따름)
        # 원본 로직: deny에 ALL:ALL 없고 allow에 ALL:ALL 있으면 -> U_28_1=0 ??? 
        # 원본 다시 확인: 
        # deny에 ALL:ALL 없으면 -> 취약
        # deny에 ALL:ALL 있고 -> allow에 ALL:ALL 있으면 -> 양호 (원본 로직이 좀 특이하지만 유지)
        if [[ -f "/etc/hosts.allow" ]]; then
             ALLOW_CHECK=$(run_cmd "[U_28_1] hosts.allow 'ALL:ALL' 설정 확인" "grep -vE '^#|^\s#' /etc/hosts.allow | grep -i 'ALL:ALL' || echo 'missing'")
             # 원본 로직: deny에 있고 allow에 있으면 -> 양호 (U_28_1=0)
             # deny에 있고 allow에 없으면 -> 양호 (언급 안됨, 기본값 0 유지)
             :
        fi
        log_basis "[U_28_1] TCP Wrapper 설정 확인 완료" "양호"
    fi
else
    run_cmd "[U_28_1] hosts.deny 파일 확인" "ls /etc/hosts.deny 2>/dev/null || echo '없음'"
    U_28_1=1
    log_basis "[U_28_1] /etc/hosts.deny 파일이 없음" "취약"
fi

# 2. [U_28_2] IPTABLES 점검
# 원본 로직: 룰이 있으면 취약(?). 보통 있으면 양호인데 원본 스크립트는 "IPTABLE이 활성화 되어있습니다 -> 취약"으로 로깅하고 있음.
# 하지만 점검 내용은 "제한 설정 여부 점검"임. 활성화 되어 있어야 제한이 되는 것.
# 원본 코드: count > 0 -> U_28_2=1 (취약). ??? 
# 사용자 제공 원본 `Ubuntu_U_28.sh`: IPTABLES_CNT > 0 -> U_28_2=1. 
# 아마도 "다른 방화벽을 써야 하는데 이게 켜져 있어서 중복"이거나 로직 반대일 수 있음. 
# **지시사항: 원본 로직 절대 유지.** 원본대로 룰 있으면 U_28_2=1로 설정.
IPT_CNT=$(run_cmd "[U_28_2] iptables 룰 개수 확인" "iptables -nL INPUT 2>/dev/null | grep -vE '^Chain|^target' | wc -l")
if [[ "$IPT_CNT" -gt 0 ]]; then
    U_28_2=1
    log_basis "[U_28_2] IPTables 룰이 존재함 (원본 기준 취약 처리)" "취약"
else
    log_basis "[U_28_2] IPTables 룰이 없음" "양호"
fi

# 3. [U_28_3] Firewalld 점검
# 원본 로직: active면 U_28_3=1 (취약). 원본 유지.
FW_STAT=$(run_cmd "[U_28_3] firewalld 상태 확인" "systemctl is-active firewalld 2>/dev/null || echo 'inactive'")
if [[ "$FW_STAT" == "active" ]]; then
    U_28_3=1
    log_basis "[U_28_3] Firewalld가 활성화됨 (원본 기준 취약 처리)" "취약"
else
    log_basis "[U_28_3] Firewalld 비활성" "양호"
fi

# 4. [U_28_4] UFW 점검
# 원본 로직: active면 U_28_4=1 (취약). 원본 유지.
UFW_STAT=$(run_cmd "[U_28_4] ufw 상태 확인" "ufw status | grep 'Status: active' || echo 'inactive'")
if [[ "$UFW_STAT" != "inactive" ]]; then
    U_28_4=1
    log_basis "[U_28_4] UFW가 활성화됨 (원본 기준 취약 처리)" "취약"
else
    log_basis "[U_28_4] UFW 비활성" "양호"
fi

# 최종 판정 (원본 로직: 하나라도 1이면 IS_VUL=1)
if [[ $U_28_1 -eq 1 || $U_28_2 -eq 1 || $U_28_3 -eq 1 || $U_28_4 -eq 1 ]]; then
    IS_VUL=1
fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
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