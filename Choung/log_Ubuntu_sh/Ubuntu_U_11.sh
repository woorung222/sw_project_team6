#!/bin/bash

# [U-11] /etc/syslog.conf 또는 rsyslog 설정파일 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-11"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_11_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 존재 여부 확인 (진단 내용 cmd 기록용)
CHECK_CONF=$(run_cmd "[U_11_1] syslog 설정 파일 존재 확인" "ls /etc/rsyslog.conf /etc/syslog.conf 2>/dev/null || echo '파일 없음'")
CHECK_DIR=$(run_cmd "[U_11_1] /etc/rsyslog.d 디렉터리 존재 확인" "ls -d /etc/rsyslog.d 2>/dev/null || echo '디렉터리 없음'")

ANY_SYSLOG=0
TARGETS=("/etc/rsyslog.conf" "/etc/syslog.conf")

# 2. 파일 상세 점검
for f in "${TARGETS[@]}"; do
    if [[ -f "$f" ]]; then
        ANY_SYSLOG=1
        U=$(run_cmd "[U_11_1] $f 소유자 확인" "stat -c '%U' '$f'")
        M=$(run_cmd "[U_11_1] $f 권한 확인" "stat -c '%a' '$f'")
        if [[ "$U" != "root" ]] || [[ "$M" -gt 644 ]] || [[ "$M" =~ [2367]$ ]]; then
            U_11_1=1
            log_basis "[U_11_1] $f 파일의 소유자($U) 또는 권한($M)이 부적절함" "취약"
        fi
    fi
done

# 3. 디렉터리 상세 점검
if [[ -d "/etc/rsyslog.d" ]]; then
    ANY_SYSLOG=1
    BAD_CONF=$(run_cmd "[U_11_1] /etc/rsyslog.d 내부 *.conf 파일 점검" "find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' \( ! -user root -o -perm /022 \) 2>/dev/null")
    if [[ -n "$BAD_CONF" ]]; then
        U_11_1=1
        log_basis "[U_11_1] /etc/rsyslog.d 내 설정 파일 권한/소유자 미흡" "취약"
    fi
fi

# 4. 최종 판정 로그
if [[ $ANY_SYSLOG -eq 0 ]]; then
    log_basis "[U_11_1] syslog 관련 설정 파일이 존재하지 않음 (안 깔려 있음)" "양호"
elif [[ $U_11_1 -eq 0 ]]; then
    log_basis "[U_11_1] 모든 syslog 관련 설정 파일 권한 및 소유자 양호" "양호"
fi

IS_VUL=$U_11_1

# --- JSON 출력 (개행 양식 엄수) ---
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
    "category": "log",
    "flag": {
      "U_11_1": $U_11_1
    },
    "timestamp": "$DATE"
  }
}
EOF