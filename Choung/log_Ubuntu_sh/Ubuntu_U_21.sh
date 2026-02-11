#!/bin/bash

# [U-21] rsyslog 설정파일 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-21"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_21_1=0; IS_VUL=0

# [U_21_1] rsyslog 설정 점검
FILES=("/etc/rsyslog.conf" "/etc/syslog.conf")
ANY_F=0
for f in "${FILES[@]}"; do
    if [[ -f "$f" ]]; then
        ANY_F=1
        U=$(run_cmd "[U_21_1] $f 소유자 확인" "stat -c '%U' '$f'")
        M=$(run_cmd "[U_21_1] $f 권한 확인" "stat -c '%a' '$f'")
        if [[ "$U" != "root" && "$U" != "bin" && "$U" != "sys" ]] || [[ "$M" -gt 640 ]]; then
            U_21_1=1
            log_basis "[U_21_1] syslog 설정 파일($f) 소유자 또는 권한 미흡" "취약"
            break
        fi
    fi
done

if [[ $ANY_F -eq 0 ]]; then
    CHECK_DIR=$(run_cmd "[U_21_1] /etc/rsyslog.d 디렉터리 확인" "ls -d /etc/rsyslog.d 2>/dev/null || echo '없음'")
    if [[ "$CHECK_DIR" == "없음" ]]; then
        log_basis "[U_21_1] syslog 관련 설정 파일이 존재하지 않음 (안 깔려 있음)" "양호"
    fi
elif [[ $U_21_1 -eq 0 ]]; then
    log_basis "[U_21_1] 모든 rsyslog 설정 파일 권한 및 소유자 양호" "양호"
fi

IS_VUL=$U_21_1

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
      "U_21_1": $U_21_1
    },
    "timestamp": "$DATE"
  }
}
EOF
