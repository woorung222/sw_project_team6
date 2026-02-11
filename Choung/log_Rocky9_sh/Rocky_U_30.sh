#!/bin/bash

# [U-30] 시스템 UMASK 값이 022 이상 설정 여부 점검
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-30"
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
U_30_1=0 # /etc/profile 점검
U_30_2=0 # /etc/login.defs 점검
IS_VUL=0

# --- [U_30_1] /etc/profile 파일 점검 ---
PROFILE="/etc/profile"

if [ -f "$PROFILE" ]; then
    CMD_PROF="grep -i '^[[:space:]]*umask' $PROFILE | grep -v '^#' | tail -n 1 | awk '{print \$2}'"
    PROFILE_UMASK=$(run_cmd "[U_30_1] /etc/profile 내 UMASK 값 추출" "$CMD_PROF")

    if [ -z "$PROFILE_UMASK" ]; then
        U_30_1=1
        log_basis "[U_30_1] /etc/profile 내 UMASK 설정이 명시되어 있지 않음" "취약"
    else
        # 원본 로직 유지 (정수 비교)
        if [ "$PROFILE_UMASK" -lt 022 ]; then
            U_30_1=1
            log_basis "[U_30_1] /etc/profile UMASK 값이 취약함 ($PROFILE_UMASK)" "취약"
        else
            U_30_1=0
            log_basis "[U_30_1] /etc/profile UMASK 설정 양호 ($PROFILE_UMASK)" "양호"
        fi
    fi
else
    U_30_1=1
    log_step "[U_30_1] 파일 확인" "ls $PROFILE" "파일 없음"
    log_basis "[U_30_1] /etc/profile 파일이 존재하지 않음" "취약"
fi

# --- [U_30_2] /etc/login.defs 파일 점검 ---
LOGIN_DEFS="/etc/login.defs"

if [ -f "$LOGIN_DEFS" ]; then
    CMD_DEFS="grep -i '^[[:space:]]*UMASK' $LOGIN_DEFS | grep -v '^#' | tail -n 1 | awk '{print \$2}'"
    LOGIN_UMASK=$(run_cmd "[U_30_2] /etc/login.defs 내 UMASK 값 추출" "$CMD_DEFS")

    if [ -z "$LOGIN_UMASK" ]; then
        U_30_2=1
        log_basis "[U_30_2] /etc/login.defs 내 UMASK 설정이 없음" "취약"
    else
        if [ "$LOGIN_UMASK" -lt 022 ]; then
            U_30_2=1
            log_basis "[U_30_2] /etc/login.defs UMASK 값이 취약함 ($LOGIN_UMASK)" "취약"
        else
            U_30_2=0
            log_basis "[U_30_2] /etc/login.defs UMASK 설정 양호 ($LOGIN_UMASK)" "양호"
        fi
    fi
else
    U_30_2=1
    log_step "[U_30_2] 파일 확인" "ls $LOGIN_DEFS" "파일 없음"
    log_basis "[U_30_2] /etc/login.defs 파일이 존재하지 않음" "취약"
fi

# --- 전체 결과 집계 ---
if [ $U_30_1 -eq 1 ] || [ $U_30_2 -eq 1 ]; then
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
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_30_1": $U_30_1,
      "U_30_2": $U_30_2
    },
    "timestamp": "$DATE"
  }
}
EOF
