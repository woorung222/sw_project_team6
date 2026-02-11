#!/bin/bash

# [U-45] 메일 서비스 버전 점검
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-45"
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
U_45_1=0; U_45_2=0; U_45_3=0; U_45_4=0; U_45_5=0; U_45_6=0; IS_VUL=0

# 1. Sendmail 점검
DET_SM=$(run_cmd "[U_45_1] Sendmail 설치/프로세스 확인" "rpm -q sendmail >/dev/null 2>&1 || ps -e -o comm | grep -xw sendmail || echo '미발견'")
if [[ "$DET_SM" != "미발견" ]]; then
    U_45_1=1
    SM_UPD=$(run_cmd "[U_45_2] Sendmail 업데이트 확인" "dnf check-update sendmail -q | grep -w sendmail || echo '최신'")
    if [[ "$SM_UPD" != "최신" ]]; then U_45_2=1; fi
else
    log_basis "[U_45_1] Sendmail 서비스 미사용" "양호"
fi

# 2. Postfix 점검
DET_PF=$(run_cmd "[U_45_3] Postfix 설치/프로세스 확인" "rpm -q postfix >/dev/null 2>&1 || ps -e -o comm | grep -xw postfix || echo '미발견'")
if [[ "$DET_PF" != "미발견" ]]; then
    U_45_3=1
    PF_UPD=$(run_cmd "[U_45_4] Postfix 업데이트 확인" "dnf check-update postfix -q | grep -w postfix || echo '최신'")
    if [[ "$PF_UPD" != "최신" ]]; then U_45_4=1; fi
else
    log_basis "[U_45_3] Postfix 서비스 미사용" "양호"
fi

# 3. Exim 점검
DET_EX=$(run_cmd "[U_45_5] Exim 설치/프로세스 확인" "rpm -q exim >/dev/null 2>&1 || ps -e -o comm | grep -xw exim || echo '미발견'")
if [[ "$DET_EX" != "미발견" ]]; then
    U_45_5=1
    EX_UPD=$(run_cmd "[U_45_6] Exim 업데이트 확인" "dnf check-update exim -q | grep -w exim || echo '최신'")
    if [[ "$EX_UPD" != "최신" ]]; then U_45_6=1; fi
else
    log_basis "[U_45_5] Exim 서비스 미사용" "양호"
fi

if [[ $U_45_2 -eq 1 || $U_45_4 -eq 1 || $U_45_6 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_45_1": $U_45_1,
      "U_45_2": $U_45_2,
      "U_45_3": $U_45_3,
      "U_45_4": $U_45_4,
      "U_45_5": $U_45_5,
      "U_45_6": $U_45_6
    },
    "timestamp": "$DATE"
  }
}
EOF
