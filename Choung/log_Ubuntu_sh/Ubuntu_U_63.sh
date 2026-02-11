#!/bin/bash

# [U-63] sudoers 파일의 권한 및 설정 적절성 점검
# 대상 : Ubuntu 24.04

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

# --- 점검 로직 수행 ---

SUDOERS_FILE="/etc/sudoers"

if [[ -f "$SUDOERS_FILE" ]]; then
    # 1. 소유자 및 권한 확인
    # 권한 문제로 stat 실패 시 sudo 사용 고려하나, 스크립트 실행 권한에 의존.
    # 여기선 run_cmd가 stderr를 dev/null로 보내므로, 읽기 실패시 처리가 필요할 수 있음.
    # 하지만 보통 점검 스크립트는 root 권한으로 실행됨을 가정.
    
    STAT_INFO=$(run_cmd "[U_63_1] sudoers 권한 확인" "stat -c '%U %a' \"$SUDOERS_FILE\"")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')

    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_63_1=1
        log_basis "[U_63_1] sudoers 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_63_1] sudoers 권한 양호 ($STAT_INFO)" "양호"
    fi

    # 2. 내용 점검 (과도한 권한 및 NOPASSWD)
    # 읽기 권한 확인
    if [[ -r "$SUDOERS_FILE" ]]; then
        # 과도한 권한 확인
        EXCESSIVE=$(run_cmd "[U_63_1] ALL=(ALL) ALL 검색" "grep -vE '^#|^root|^%sudo|^%admin|^Defaults' \"$SUDOERS_FILE\" | grep 'ALL=(ALL' | grep 'ALL' || echo 'none'")
        
        # NOPASSWD 확인
        NOPASS=$(run_cmd "[U_63_1] NOPASSWD 검색" "grep -v '^#' \"$SUDOERS_FILE\" | grep 'NOPASSWD' || echo 'none'")

        if [[ "$EXCESSIVE" != "none" ]] || [[ "$NOPASS" != "none" ]]; then
            U_63_1=1
            log_basis "[U_63_1] 취약 설정 발견: Excessive($EXCESSIVE), NOPASSWD($NOPASS)" "취약"
        else
            log_basis "[U_63_1] sudoers 내부 설정 양호" "양호"
        fi
    else
        # 읽기 권한 없음 (root 실행 아니면 발생 가능)
        U_63_1=1
        log_basis "[U_63_1] sudoers 파일을 읽을 수 없음 (권한 부족)" "취약"
    fi

else
    TMP=$(run_cmd "[U_63_1] sudoers 파일 확인" "ls /etc/sudoers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_63_1] /etc/sudoers 파일이 존재하지 않음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_63_1 -eq 1 ]]; then
    IS_VUL=1
fi

# JSON 출력
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
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_63_1": $U_63_1
    },
    "timestamp": "$DATE"
  }
}
EOF
