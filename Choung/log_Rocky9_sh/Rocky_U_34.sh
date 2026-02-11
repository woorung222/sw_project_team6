#!/bin/bash

# [U-34] Finger 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

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

U_34_1=0; U_34_2=0; U_34_3=0

# --- 점검 로직 시작 ---

# ---------------------------------------------------------
# 1. [U_34_1] inetd.conf 설정 점검
# ---------------------------------------------------------
INETD_FILE="/etc/inetd.conf"
if [ -f "$INETD_FILE" ]; then
    CHECK_INETD=$(run_cmd "[U_34_1] inetd.conf 내 finger 설정 확인" "grep -v '^#' $INETD_FILE | grep -iw 'finger'")
    
    if [ -n "$CHECK_INETD" ]; then
        U_34_1=1
        log_basis "[U_34_1] inetd.conf 파일에서 finger 서비스 활성화 설정이 발견됨" "취약"
    else
        U_34_1=0
        log_basis "[U_34_1] inetd.conf 파일 내 finger 서비스 설정이 없음" "양호"
    fi
else
    log_step "[U_34_1] inetd.conf 파일 존재 여부" "[ -f $INETD_FILE ]" "파일 없음"
    U_34_1=0
    log_basis "[U_34_1] inetd.conf 파일이 존재하지 않음" "양호"
fi

# ---------------------------------------------------------
# 2. [U_34_2] xinetd 설정 점검
# ---------------------------------------------------------
XINETD_FILE="/etc/xinetd.d/finger"
if [ -f "$XINETD_FILE" ]; then
    CHECK_XINETD=$(run_cmd "[U_34_2] xinetd.d/finger 설정 확인" "grep -i 'disable' $XINETD_FILE | grep -iw 'no'")
    
    if [ -n "$CHECK_XINETD" ]; then
        U_34_2=1
        log_basis "[U_34_2] xinetd.d/finger 설정에서 disable=no가 확인됨" "취약"
    else
        U_34_2=0
        log_basis "[U_34_2] xinetd.d/finger 설정이 비활성화(disable=yes) 되어있음" "양호"
    fi
else
    log_step "[U_34_2] xinetd.d/finger 파일 존재 여부" "[ -f $XINETD_FILE ]" "파일 없음"
    U_34_2=0
    log_basis "[U_34_2] xinetd.d/finger 설정 파일이 존재하지 않음" "양호"
fi

# ---------------------------------------------------------
# 3. [U_34_3] Systemd 및 프로세스 점검
# ---------------------------------------------------------
CHECK_SYSTEMD=$(run_cmd "[U_34_3] Systemd 서비스 활성 여부" "systemctl is-active finger.socket finger.service 2>/dev/null | grep -w 'active'")
CHECK_PROC=$(run_cmd "[U_34_3] Finger 프로세스 실행 여부" "ps -e -o comm | grep -v 'grep' | grep -xw 'fingerd'")

if [[ -n "$CHECK_SYSTEMD" ]]; then
    U_34_3=1
    log_basis "[U_34_3] Systemd에서 finger 서비스가 활성화(Active) 상태임" "취약"
elif [[ -n "$CHECK_PROC" ]]; then
    U_34_3=1
    log_basis "[U_34_3] fingerd 프로세스가 현재 실행 중임" "취약"
else
    U_34_3=0
    log_basis "[U_34_3] Finger 서비스 비활성 및 프로세스 미실행 확인됨" "양호"
fi

# ---------------------------------------------------------
# 4. 전체 취약 여부 판단
# ---------------------------------------------------------
IS_VUL=0
if [[ $U_34_1 -eq 1 ]] || [[ $U_34_2 -eq 1 ]] || [[ $U_34_3 -eq 1 ]]; then
    IS_VUL=1
fi

# ---------------------------------------------------------
# 5. [결과 출력] 최종 JSON 출력 (stdout)
# ---------------------------------------------------------
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
      "U_34_1": $U_34_1,
      "U_34_2": $U_34_2,
      "U_34_3": $U_34_3
    },
    "timestamp": "$DATE"
  }
}
EOF