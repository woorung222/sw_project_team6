#!/bin/bash

# [U-55] FTP 기본 계정에 쉘 설정 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-55"
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
U_55_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_55_1] ftp 계정의 로그인 쉘 확인
FTP_ACCOUNT=$(run_cmd "[U_55_1] ftp 계정 검색" "grep '^ftp:' /etc/passwd || echo 'none'")

if [[ "$FTP_ACCOUNT" != "none" ]]; then
    FTP_SHELL=$(echo "$FTP_ACCOUNT" | cut -d: -f7)
    
    if [[ "$FTP_SHELL" != "/bin/false" && "$FTP_SHELL" != "/sbin/nologin" && "$FTP_SHELL" != "/usr/sbin/nologin" ]]; then
        U_55_1=1
        log_basis "[U_55_1] ftp 계정 쉘이 로그인 가능 쉘임: $FTP_SHELL" "취약"
    else
        log_basis "[U_55_1] ftp 계정 쉘 제한됨: $FTP_SHELL" "양호"
    fi
else
    U_55_1=0
    # 위 run_cmd 결과가 'none'이므로 이게 증빙이 됨
    log_basis "[U_55_1] ftp 계정 미존재" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_55_1 -eq 1 ]]; then
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
      "U_55_1": $U_55_1
    },
    "timestamp": "$DATE"
  }
}
EOF
