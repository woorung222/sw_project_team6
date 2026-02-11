#!/bin/bash

# [U-67] /var/log 내 모든 로그 파일의 소유자 및 권한 전수 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-67"
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
U_67_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

LOG_DIR="/var/log"

if [[ -d "$LOG_DIR" ]]; then
    # 취약 파일 검색 (소유자!=root OR 권한>644)
    # -quit 옵션으로 최초 1개만 찾고 종료 (성능 최적화)
    VULN_FILE=$(run_cmd "[U_67_1] 취약 권한 로그 파일 검색" "sudo find \"$LOG_DIR\" -type f \( -not -user root -o -perm /022 \) -print -quit 2>/dev/null || echo 'none'")
    
    if [[ "$VULN_FILE" != "none" ]] && [[ -n "$VULN_FILE" ]]; then
        U_67_1=1
        # 발견된 파일의 상세 정보 로깅
        FILE_INFO=$(run_cmd "[U_67_1] 상세 정보 확인" "ls -l \"$VULN_FILE\"")
        log_basis "[U_67_1] 권한/소유자 취약 로그 파일 발견: $FILE_INFO (외 다수 가능성)" "취약"
    else
        log_basis "[U_67_1] /var/log 내 취약한 권한/소유자 설정 파일 없음" "양호"
    fi
else
    # 디렉토리 없음 증빙
    TMP=$(run_cmd "[U_67_1] 로그 디렉토리 확인" "ls -d /var/log 2>/dev/null || echo '미존재'")
    U_67_1=0
    log_basis "[U_67_1] /var/log 디렉토리가 존재하지 않음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_67_1 -eq 1 ]]; then
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
    "is_auto": 1,
    "category": "log",
    "flag": {
      "U_67_1": $U_67_1
    },
    "timestamp": "$DATE"
  }
}
EOF
