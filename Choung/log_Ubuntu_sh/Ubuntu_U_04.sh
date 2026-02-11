#!/bin/bash

# [U-04] 패스워드 파일 보호
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-04"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_04_1=1; IS_VUL=0

# 1. /etc/passwd 점검
P_OWNER=$(run_cmd "[U_04_1] /etc/passwd 소유자 확인" "stat -c '%U' /etc/passwd")
P_PERM=$(run_cmd "[U_04_1] /etc/passwd 권한 확인" "stat -c '%a' /etc/passwd")

# 2. /etc/shadow 점검
S_OWNER=$(run_cmd "[U_04_1] /etc/shadow 소유자 확인" "stat -c '%U' /etc/shadow")
S_PERM=$(run_cmd "[U_04_1] /etc/shadow 권한 확인" "stat -c '%a' /etc/shadow")

# 3. 빈 비밀번호 계정 점검
EMPTY_PW=$(run_cmd "[U_04_1] 빈 비밀번호 계정 확인" "awk -F: '(\$2==\"\"){print \$1}' /etc/shadow || echo '없음'")

# 판정 로직
if [[ "$P_OWNER" == "root" ]] && [ "$P_PERM" -le 644 ] && \
   ([[ "$S_OWNER" == "root" ]] || [[ "$S_OWNER" == "shadow" ]]) && [ "${S_PERM: -1}" -eq 0 ] && \
   ([[ -z "$EMPTY_PW" ]] || [[ "$EMPTY_PW" == "없음" ]]); then
    U_04_1=0
    log_basis "[U_04_1] 패스워드 및 쉐도우 파일 보호 설정 양호" "양호"
else
    U_04_1=1
    log_basis "[U_04_1] 패스워드 파일 권한 미흡 또는 빈 비밀번호 계정 존재" "취약"
fi

IS_VUL=$U_04_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_04_1": $U_04_1
    },
    "timestamp": "$DATE"
  }
}
EOF
