#!/bin/bash

# [U-42] 불필요한 RPC 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-42"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기화
U_42_1=0; U_42_2=0; U_42_3=0; IS_VUL=0

# RPC 서비스 리스트
RPC_LIST="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

# --- 점검 로직 시작 ---

# 1. [U_42_1] inetd.conf 점검
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(run_cmd "[U_42_1] inetd.conf RPC 서비스 확인" "grep -v '^#' /etc/inetd.conf | grep -iE \"$RPC_LIST\" || echo 'none'")
    if [[ "$INETD_CHECK" != "none" ]]; then
        U_42_1=1
        log_basis "[U_42_1] inetd.conf에 불필요한 RPC 서비스가 설정됨" "취약"
    else
        log_basis "[U_42_1] inetd.conf에 불필요한 RPC 서비스 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_42_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
    log_basis "[U_42_1] inetd.conf 파일이 존재하지 않음" "양호"
fi

# 2. [U_42_2] xinetd.d 점검
if [[ -d "/etc/xinetd.d" ]]; then
    XINETD_CHECK=$(run_cmd "[U_42_2] xinetd.d RPC 서비스 확인" "grep -rEi 'disable.*=.*no' /etc/xinetd.d/ 2>/dev/null | grep -iE \"$RPC_LIST\" || echo 'none'")
    if [[ "$XINETD_CHECK" != "none" ]]; then
        U_42_2=1
        log_basis "[U_42_2] xinetd 설정에서 불필요한 RPC 서비스 활성화됨" "취약"
    else
        log_basis "[U_42_2] xinetd 설정에서 불필요한 RPC 서비스 발견되지 않음" "양호"
    fi
else
    TMP=$(run_cmd "[U_42_2] xinetd.d 디렉토리 확인" "ls -d /etc/xinetd.d 2>/dev/null || echo '없음'")
    log_basis "[U_42_2] xinetd.d 디렉토리가 존재하지 않음" "양호"
fi

# 3. [U_42_3] Systemd 및 rpcinfo 점검
# Systemd 확인
SYSTEMD_CHECK=$(run_cmd "[U_42_3] Systemd RPC 서비스 확인" "systemctl list-unit-files 2>/dev/null | grep -iE \"$RPC_LIST\" | grep 'enabled' || echo 'none'")

# rpcinfo 확인
if command -v rpcinfo >/dev/null 2>&1; then
    RPCINFO_CHECK=$(run_cmd "[U_42_3] rpcinfo 동적 포트 확인" "rpcinfo -p 2>/dev/null | grep -iE \"$RPC_LIST\" || echo 'none'")
else
    RPCINFO_CHECK="none"
    run_cmd "[U_42_3] rpcinfo 명령 확인" "echo 'rpcinfo command not found'"
fi

if [[ "$SYSTEMD_CHECK" != "none" ]] || [[ "$RPCINFO_CHECK" != "none" ]]; then
    U_42_3=1
    log_basis "[U_42_3] Systemd 또는 rpcinfo에서 불필요한 RPC 서비스 활성화 확인" "취약"
else
    log_basis "[U_42_3] Systemd 및 rpcinfo 점검 결과 특이사항 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_42_1 -eq 1 || $U_42_2 -eq 1 || $U_42_3 -eq 1 ]]; then
    IS_VUL=1
fi

# JSON 출력
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
    "category": "service",
    "flag": {
      "U_42_1": $U_42_1,
      "U_42_2": $U_42_2,
      "U_42_3": $U_42_3
    },
    "timestamp": "$DATE"
  }
}
EOF
