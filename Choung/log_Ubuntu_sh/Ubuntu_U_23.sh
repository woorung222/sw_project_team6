#!/bin/bash

# [U-23] SUID, SGID 설정 파일 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-23"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_23_1=0; IS_VUL=0

# 가이드 기준 점검 대상 주요 실행 파일
executables=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpr" "/usr/bin/lprm" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/traceroute")

# [U_23_1] 주요 파일 SUID/SGID 점검
for f in "${executables[@]}"; do
    CHECK_F=$(run_cmd "[U_23_1] $f 파일 존재 확인" "ls $f 2>/dev/null || echo '없음'")
    if [[ "$CHECK_F" != "없음" ]]; then
        # SUID/SGID 포함 비트 확인 (stat %a의 첫 자리가 2, 4, 6 중 하나인지 체크)
        PERM=$(run_cmd "[U_23_1] $f 권한 숫자 확인" "stat -c '%a' '$f'")
        if [[ ${#PERM} -eq 4 ]] && [[ "${PERM:0:1}" =~ [246] ]]; then
            U_23_1=1
            log_basis "[U_23_1] 주요 실행 파일($f)에 불필요한 SUID/SGID 설정이 발견됨" "취약"
            break
        fi
    fi
done

if [[ $U_23_1 -eq 0 ]]; then
    log_basis "[U_23_1] 주요 실행 파일 내 SUID/SGID 취약 설정이 발견되지 않음" "양호"
fi

IS_VUL=$U_23_1

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
      "U_23_1": $U_23_1
    },
    "timestamp": "$DATE"
  }
}
EOF
