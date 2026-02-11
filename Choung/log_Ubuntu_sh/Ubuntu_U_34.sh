#!/bin/bash

# [U-34] Finger 서비스 비활성화
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-34"
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
U_34_1=0; U_34_2=0; U_34_3=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_34_1] inetd 설정 확인
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(run_cmd "[U_34_1] inetd.conf 내 finger 서비스 확인" "grep -v '^#' /etc/inetd.conf | grep 'finger' || echo 'none'")
    if [[ "$INETD_CHECK" != "none" ]]; then
        U_34_1=1
        log_basis "[U_34_1] inetd.conf에 finger 서비스가 활성화되어 있음" "취약"
    else
        log_basis "[U_34_1] inetd.conf에 finger 서비스 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_34_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
    log_basis "[U_34_1] inetd.conf 파일이 없음 (안 깔려 있음)" "양호"
fi

# 2. [U_34_2] xinetd 설정 확인
if [[ -f "/etc/xinetd.d/finger" ]]; then
    XINETD_CHECK=$(run_cmd "[U_34_2] xinetd finger 설정 확인" "grep 'disable[[:space:]]*=[[:space:]]*yes' /etc/xinetd.d/finger || echo 'active'")
    if [[ "$XINETD_CHECK" == "active" ]]; then
        U_34_2=1
        log_basis "[U_34_2] xinetd.d/finger 서비스가 비활성화(disable=yes)되지 않음" "취약"
    else
        log_basis "[U_34_2] xinetd finger 서비스 비활성화됨" "양호"
    fi
else
    TMP=$(run_cmd "[U_34_2] xinetd.d/finger 파일 확인" "ls /etc/xinetd.d/finger 2>/dev/null || echo '없음'")
    log_basis "[U_34_2] xinetd finger 설정 파일이 없음 (안 깔려 있음)" "양호"
fi

# 3. [U_34_3] Systemd 서비스 및 프로세스/포트 확인
PROC_CHECK=$(run_cmd "[U_34_3] finger 프로세스 확인" "ps -ef | grep -E 'fingerd|cfingerd|efingerd' | grep -v 'grep' || echo 'none'")
PORT_CHECK=$(run_cmd "[U_34_3] finger 포트(79) 확인" "netstat -antp 2>/dev/null | grep ':79 ' | grep 'LISTEN' || echo 'none'")

if [[ "$PROC_CHECK" != "none" ]] || [[ "$PORT_CHECK" != "none" ]]; then
    U_34_3=1
    log_basis "[U_34_3] finger 프로세스 또는 포트(79)가 활성화되어 있음" "취약"
else
    log_basis "[U_34_3] finger 관련 프로세스 및 포트 미발견" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_34_1 -eq 1 || $U_34_2 -eq 1 || $U_34_3 -eq 1 ]]; then
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
    "flag_id": "U-34",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_34_1": $U_34_1,
      "U_34_2": $U_34_2,
      "U_34_3": $U_34_3
    },
    "timestamp": "$DATE"
  }
}
EOF
