#!/bin/bash

# [U-37] cron 및 at 관련 파일(명령어, 작업 목록, 설정 파일)의 소유자 및 권한 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-37"
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
U_37_1=0; U_37_2=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_37_1] cron 관련 파일 점검
# 1-1. crontab 명령어 점검
CRON_BIN="/usr/bin/crontab"
CHECK_BIN=$(run_cmd "[U_37_1] $CRON_BIN 존재 확인" "ls $CRON_BIN 2>/dev/null || echo '없음'")

if [[ "$CHECK_BIN" != "없음" ]]; then
    CMD_OWNER=$(run_cmd "[U_37_1] $CRON_BIN 소유자 확인" "stat -c '%U' $CRON_BIN")
    CMD_PERM=$(run_cmd "[U_37_1] $CRON_BIN 권한(Others) 확인" "stat -c '%A' $CRON_BIN | cut -c 10")
    
    if [[ "$CMD_OWNER" != "root" || "$CMD_PERM" != "-" ]]; then
        U_37_1=1
        log_basis "[U_37_1] $CRON_BIN 소유자($CMD_OWNER) 또는 권한($CMD_PERM) 미흡" "취약"
    else
        log_basis "[U_37_1] $CRON_BIN 소유자 및 권한 양호" "양호"
    fi
else
    log_basis "[U_37_1] $CRON_BIN 파일이 없음 (cron 미설치 가능성)" "양호"
fi

# 1-2. cron spool 점검
CRON_SPOOL="/var/spool/cron/crontabs"
CHECK_SPOOL=$(run_cmd "[U_37_1] cron spool($CRON_SPOOL) 확인" "ls -d $CRON_SPOOL 2>/dev/null || echo '없음'")

if [[ "$CHECK_SPOOL" != "없음" ]]; then
    # 소유자 root 아님 OR 권한 640 초과(others 읽기/쓰기/실행 존재 등)
    BAD_SPOOL=$(run_cmd "[U_37_1] cron spool 내 취약 파일 검색" "find $CRON_SPOOL -type f \( ! -user root -o -perm /027 \) 2>/dev/null || echo ''")
    if [[ -n "$BAD_SPOOL" ]]; then
        U_37_1=1
        log_basis "[U_37_1] cron spool 내 소유자/권한 취약 파일 발견" "취약"
    else
        log_basis "[U_37_1] cron spool 내 파일 권한 양호" "양호"
    fi
else
    log_basis "[U_37_1] cron spool 디렉터리가 없음" "양호"
fi

# 1-3. /etc/cron* 설정 파일 점검
ETC_CRON_FILES=$(run_cmd "[U_37_1] /etc/cron* 파일 목록 확인" "find /etc -maxdepth 1 -name 'cron*' 2>/dev/null")
if [[ -n "$ETC_CRON_FILES" ]]; then
    for f in $ETC_CRON_FILES; do
        F_OWNER=$(stat -c "%U" "$f")
        F_PERM=$(stat -c "%a" "$f")
        if [[ "$F_OWNER" != "root" || "$F_PERM" -gt 640 ]]; then
            U_37_1=1
            log_basis "[U_37_1] $f 소유자($F_OWNER) 또는 권한($F_PERM) 미흡" "취약"
        fi
    done
fi
if [[ $U_37_1 -eq 0 ]]; then log_basis "[U_37_1] cron 관련 설정 파일 권한 양호" "양호"; fi


# 2. [U_37_2] at 관련 파일 점검
# 2-1. at 명령어 점검
AT_BIN="/usr/bin/at"
CHECK_AT=$(run_cmd "[U_37_2] $AT_BIN 존재 확인" "ls $AT_BIN 2>/dev/null || echo '없음'")

if [[ "$CHECK_AT" != "없음" ]]; then
    AT_OWNER=$(run_cmd "[U_37_2] $AT_BIN 소유자 확인" "stat -c '%U' $AT_BIN")
    AT_PERM=$(run_cmd "[U_37_2] $AT_BIN 권한(Others) 확인" "stat -c '%A' $AT_BIN | cut -c 10")
    
    if [[ "$AT_OWNER" != "root" || "$AT_PERM" != "-" ]]; then
        U_37_2=1
        log_basis "[U_37_2] $AT_BIN 소유자($AT_OWNER) 또는 권한 미흡" "취약"
    else
        log_basis "[U_37_2] $AT_BIN 소유자 및 권한 양호" "양호"
    fi
else
    log_basis "[U_37_2] $AT_BIN 파일이 없음 (at 미설치)" "양호"
fi

# 2-2. at spool 점검
AT_SPOOL="/var/spool/cron/atjobs"
CHECK_AT_SPOOL=$(run_cmd "[U_37_2] at spool($AT_SPOOL) 확인" "ls -d $AT_SPOOL 2>/dev/null || echo '없음'")

if [[ "$CHECK_AT_SPOOL" != "없음" ]]; then
    BAD_AT=$(run_cmd "[U_37_2] at spool 내 취약 파일 검색" "find $AT_SPOOL -type f \( ! -user root -o -perm /027 \) 2>/dev/null || echo ''")
    if [[ -n "$BAD_AT" ]]; then
        U_37_2=1
        log_basis "[U_37_2] at spool 내 소유자/권한 취약 파일 발견" "취약"
    else
        log_basis "[U_37_2] at spool 내 파일 권한 양호" "양호"
    fi
else
    log_basis "[U_37_2] at spool 디렉터리가 없음" "양호"
fi

if [[ $U_37_1 -eq 1 || $U_37_2 -eq 1 ]]; then IS_VUL=1; fi

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
    "category": "service",
    "flag": {
      "U_37_1": $U_37_1,
      "U_37_2": $U_37_2
    },
    "timestamp": "$DATE"
  }
}
EOF