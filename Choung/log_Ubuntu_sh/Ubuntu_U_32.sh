#!/bin/bash

# [U-32] 홈 디렉토리로 지정한 디렉토리의 존재 관리
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-32"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_32_1=0; IS_VUL=0

# 1. [U_32_1] 홈 디렉터리 설정 점검
# 1-1. 미지정 계정 확인
NULL_HOME=$(run_cmd "[U_32_1] 홈 디렉터리 미지정 계정 검색" "awk -F: '\$7!=\"/bin/false\" && \$7!=\"/sbin/nologin\" && \$6==\"\" {print \$1}' /etc/passwd || echo 'none'")
if [[ "$NULL_HOME" != "none" && -n "$NULL_HOME" ]]; then
    U_32_1=1
    log_basis "[U_32_1] 홈 디렉터리 미지정 계정 발견: $NULL_HOME" "취약"
fi

# 1-2. '/' 홈 계정 확인
SLASH_HOME=$(run_cmd "[U_32_1] 홈이 '/'인 일반 계정 검색" "awk -F: '\$7!=\"/bin/false\" && \$7!=\"/sbin/nologin\" && \$1!=\"root\" && \$6==\"/\" {print \$1}' /etc/passwd || echo 'none'")
if [[ "$SLASH_HOME" != "none" && -n "$SLASH_HOME" ]]; then
    U_32_1=1
    log_basis "[U_32_1] 홈 디렉터리가 '/'인 일반 계정 발견: $SLASH_HOME" "취약"
fi

if [[ $U_32_1 -eq 0 ]]; then
    log_basis "[U_32_1] 홈 디렉터리 설정 양호" "양호"
fi

IS_VUL=$U_32_1

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
      "U_32_1": $U_32_1
    },
    "timestamp": "$DATE"
  }
}
EOF
