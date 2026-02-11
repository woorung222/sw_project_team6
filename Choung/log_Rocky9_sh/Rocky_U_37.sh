#!/bin/bash

# [U-37] crontab 설정파일 권한 설정 미흡
# 대상 운영체제 : Rocky Linux 9

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

# 1. [U_37_1] Cron 명령어/설정파일 점검
CRON_BIN="/usr/bin/crontab"
if [[ -f "$CRON_BIN" ]]; then
    B_PERM=$(run_cmd "[U_37_1] crontab 명령어 권한 확인" "stat -c '%a' '$CRON_BIN'")
    if [[ "$B_PERM" -ge 4000 ]] || [[ $((B_PERM % 10 % 2)) -eq 1 ]]; then U_37_1=1; fi
fi

CHECK_LIST=("/etc/crontab" "/etc/cron.allow" "/etc/cron.deny" "/var/spool/cron")
for file in "${CHECK_LIST[@]}"; do
    if [[ -f "$file" ]]; then
        O=$(run_cmd "[U_37_1] $file 소유자 확인" "stat -c '%U' '$file'")
        P=$(run_cmd "[U_37_1] $file 권한 확인" "stat -c '%a' '$file'")
        if [[ "$O" != "root" ]] || [[ "$P" -gt 640 ]]; then U_37_1=1; fi
    elif [[ -d "$file" ]]; then
        D_CHK=$(run_cmd "[U_37_1] $file 내 취약 파일 검색" "find '$file' -type f \( ! -user root -o -perm /027 \) -print -quit")
        if [[ -n "$D_CHK" ]]; then U_37_1=1; fi
    fi
done

CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
for dir in "${CRON_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        D_ALL=$(run_cmd "[U_37_1] $dir 내부 취약 설정 파일 전수 점검" "find '$dir' -type f \( ! -user root -o -perm /027 \) -print -quit")
        if [[ -n "$D_ALL" ]]; then U_37_1=1; fi
    fi
done
log_basis "[U_37_1] Cron 관련 설정 취약 여부" "$([[ $U_37_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_37_2] At 명령어/설정파일 점검 (복구 완료)
AT_BIN="/usr/bin/at"
if [[ -f "$AT_BIN" ]]; then
    A_PERM=$(run_cmd "[U_37_2] at 명령어 권한 확인" "stat -c '%a' '$AT_BIN'")
    if [[ "$A_PERM" -ge 4000 ]] || [[ $((A_PERM % 10 % 2)) -eq 1 ]]; then U_37_2=1; fi
fi

AT_FILES=("/etc/at.allow" "/etc/at.deny")
for file in "${AT_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        AO=$(run_cmd "[U_37_2] $file 소유자 확인" "stat -c '%U' '$file'")
        AP=$(run_cmd "[U_37_2] $file 권한 확인" "stat -c '%a' '$file'")
        if [[ "$AO" != "root" ]] || [[ "$AP" -gt 640 ]]; then U_37_2=1; fi
    else
        log_step "[U_37_2] 파일 확인" "ls $file" "파일 없음"
    fi
done
log_basis "[U_37_2] At 관련 설정 취약 여부" "$([[ $U_37_2 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_37_1 -eq 1 ]] || [[ $U_37_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
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