#!/bin/bash

# [U-17] 시스템 시작 스크립트 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 
#   U_17_1 : /etc/rc.d 내 파일 소유자가 root이고, other 쓰기 권한이 없는 경우
#   U_17_2 : /etc/systemd/system 내 파일 소유자가 root이고, other 쓰기 권한이 없는 경우

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-17"
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

# 초기 상태 설정
U_17_1=0 
U_17_2=0
IS_VUL=0

# --- [U_17_1] Init 스크립트 점검 (/etc/rc.d) ---
INIT_DIR="/etc/rc.d"

if [ -d "$INIT_DIR" ]; then
    CMD_FIND_INIT="find -L $INIT_DIR -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null"
    VULN_INIT=$(run_cmd "[U_17_1] /etc/rc.d 내 취약 파일 검색" "$CMD_FIND_INIT")
    
    if [ -z "$VULN_INIT" ]; then
        U_17_1=0
        log_basis "[U_17_1] /etc/rc.d 내 취약한 권한의 파일이 없음" "양호"
    else
        U_17_1=1
        log_basis "[U_17_1] /etc/rc.d 내 취약 파일 발견: $VULN_INIT" "취약"
    fi
else
    U_17_1=0
    log_basis "[U_17_1] /etc/rc.d 디렉터리가 존재하지 않음(양호)" "양호"
fi

# --- [U_17_2] Systemd 유닛 파일 점검 (/etc/systemd/system) ---
SYSTEMD_DIR="/etc/systemd/system"

if [ -d "$SYSTEMD_DIR" ]; then
    CMD_FIND_SYS="find -L $SYSTEMD_DIR -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null"
    VULN_SYSTEMD=$(run_cmd "[U_17_2] /etc/systemd/system 내 취약 파일 검색" "$CMD_FIND_SYS")
    
    if [ -z "$VULN_SYSTEMD" ]; then
        U_17_2=0
        log_basis "[U_17_2] /etc/systemd/system 내 취약한 권한의 파일이 없음" "양호"
    else
        U_17_2=1
        log_basis "[U_17_2] /etc/systemd/system 내 취약 파일 발견: $VULN_SYSTEMD" "취약"
    fi
else
    U_17_2=0
    log_basis "[U_17_2] /etc/systemd/system 디렉터리가 존재하지 않음(양호)" "양호"
fi

# --- 전체 결과 집계 ---
if [ $U_17_1 -eq 1 ] || [ $U_17_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
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
    "flag_id": "U-17",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_17_1": $U_17_1,
      "U_17_2": $U_17_2
    },
    "timestamp": "$DATE"
  }
}
EOF
