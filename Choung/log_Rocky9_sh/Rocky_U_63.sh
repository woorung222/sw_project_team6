#!/bin/bash

# [U-63] sudo 명령어 접근 관리
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-63"
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
U_63_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 패키지 설치 확인
S_PKG=$(run_cmd "[63] sudo 패키지 설치 확인" "rpm -qa | grep -qE '^sudo-[0-9]' && echo '설치됨' || echo '안 깔려 있음'")

if [[ "$S_PKG" == "설치됨" ]]; then
    if [[ -f "/etc/sudoers" ]]; then
        O=$(run_cmd "[U_63_1] /etc/sudoers 소유자 확인" "stat -c '%U' /etc/sudoers")
        P=$(run_cmd "[U_63_1] /etc/sudoers 권한 확인" "stat -c '%a' /etc/sudoers")
        if [[ "$O" != "root" ]] || [[ "$P" -gt 640 ]]; then
            U_63_1=1
            log_basis "[U_63_1] /etc/sudoers 소유자($O) 또는 권한($P) 미흡" "취약"
        else
            log_basis "[U_63_1] /etc/sudoers 설정 양호" "양호"
        fi
    else
        log_step "[U_63_1] 파일 확인" "ls /etc/sudoers" "파일 없음"
    fi
else
    log_basis "[U_63_1] sudo 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

IS_VUL=$U_63_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-63",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service_management",
    "flag": { 
      "U_63_1": $U_63_1 
    },
    "timestamp": "$DATE"
  }
}
EOF
