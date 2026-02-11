#!/bin/bash

# [U-20] /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-20"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_20_1=0; U_20_2=0; U_20_3=0; IS_VUL=0

# [U_20_1] inetd.conf 점검
CHECK_I=$(run_cmd "[U_20_1] /etc/inetd.conf 존재 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
if [[ "$CHECK_I" != "없음" ]]; then
    U=$(run_cmd "[U_20_1] inetd.conf 소유자 확인" "stat -c '%U' /etc/inetd.conf")
    M=$(run_cmd "[U_20_1] inetd.conf 권한 확인" "stat -c '%a' /etc/inetd.conf")
    if [[ "$U" != "root" ]] || [[ "$M" -gt 600 ]]; then
        U_20_1=1
        log_basis "[U_20_1] inetd.conf 설정 미흡 (소유자: $U, 권한: $M)" "취약"
    else
        log_basis "[U_20_1] inetd.conf 설정 양호" "양호"
    fi
else
    log_basis "[U_20_1] /etc/inetd.conf 파일이 없음 (안 깔려 있음)" "양호"
fi

# [U_20_2] xinetd.conf 및 xinetd.d 점검
CHECK_X=$(run_cmd "[U_20_2] /etc/xinetd.conf 및 디렉터리 확인" "ls -d /etc/xinetd.conf /etc/xinetd.d 2>/dev/null || echo '없음'")
if [[ "$CHECK_X" != "없음" ]]; then
    BAD_X=$(run_cmd "[U_20_2] xinetd 관련 파일 권한/소유자 점검" "find /etc/xinetd.conf /etc/xinetd.d -maxdepth 1 -type f \( ! -user root -o -perm /077 \) 2>/dev/null")
    if [[ -n "$BAD_X" ]]; then
        U_20_2=1
        log_basis "[U_20_2] xinetd 설정 파일 중 권한 또는 소유자 미흡 항목 발견" "취약"
    else
        log_basis "[U_20_2] xinetd 관련 설정 파일 설정 양호" "양호"
    fi
else
    log_basis "[U_20_2] xinetd 관련 설정이 존재하지 않음 (안 깔려 있음)" "양호"
fi

# [U_20_3] systemd 설정 점검
VULN_S=$(run_cmd "[U_20_3] /etc/systemd 내 유닛 파일 권한 점검" "find /etc/systemd -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null")
if [[ -n "$VULN_S" ]]; then
    U_20_3=1
    log_basis "[U_20_3] systemd 설정 파일 중 소유자가 root가 아니거나 쓰기 권한이 발견됨" "취약"
else
    log_basis "[U_20_3] systemd 설정 파일 권한 양호" "양호"
fi

if [[ $U_20_1 -eq 1 ]] || [[ $U_20_2 -eq 1 ]] || [[ $U_20_3 -eq 1 ]]; then IS_VUL=1; fi

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
      "U_20_1": $U_20_1,
      "U_20_2": $U_20_2,
      "U_20_3": $U_20_3
    },
    "timestamp": "$DATE"
  }
}
EOF