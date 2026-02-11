#!/bin/bash

# [U-40] /etc/exports 파일의 권한 및 접근 제어 설정 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-40"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_40_1=0; U_40_2=0; IS_VUL=0

# 1. [U_40_1] /etc/exports 소유자 및 권한 점검
if [[ -f "/etc/exports" ]]; then
    OWNER=$(run_cmd "[U_40_1] /etc/exports 소유자 확인" "stat -c '%U' /etc/exports")
    PERM=$(run_cmd "[U_40_1] /etc/exports 권한 확인" "stat -c '%a' /etc/exports")
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 644 ]]; then
        U_40_1=1
        log_basis "[U_40_1] /etc/exports 소유자($OWNER) 또는 권한($PERM) 미흡" "취약"
    else
        log_basis "[U_40_1] /etc/exports 권한 및 소유자 양호" "양호"
    fi
else
    TMP=$(run_cmd "[U_40_1] /etc/exports 파일 확인" "ls /etc/exports 2>/dev/null || echo '없음'")
    log_basis "[U_40_1] /etc/exports 파일 없음 (NFS 미사용 추정)" "양호"
    # 파일 없으면 U_40_2도 자동 양호로 처리됨 (아래 로직 상 파일 체크 안 들어가므로)
fi

# 2. [U_40_2] /etc/exports 내용 점검
if [[ -f "/etc/exports" ]]; then
    # 취약 키워드 검색
    VULN_CHECK=$(run_cmd "[U_40_2] /etc/exports 내 취약 옵션 확인" "grep -v '^#' /etc/exports | grep -v '^$' | grep -E '\*|no_root_squash|insecure' || echo 'none'")
    
    if [[ "$VULN_CHECK" != "none" ]]; then
        U_40_2=1
        log_basis "[U_40_2] /etc/exports에 취약 설정(*, no_root_squash 등) 존재" "취약"
    else
        log_basis "[U_40_2] /etc/exports 내 취약 설정 미발견" "양호"
    fi
else
    log_basis "[U_40_2] /etc/exports 파일 없음" "양호"
fi

if [[ $U_40_1 -eq 1 || $U_40_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-40",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_40_1": $U_40_1,
      "U_40_2": $U_40_2
    },
    "timestamp": "$DATE"
  }
}
EOF
