#!/bin/bash

# [U-14] root 홈, 패스 디렉터리 권한 및 패스 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-14"
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
U_14_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# [U_14_1] PATH 환경변수 내 "." 또는 "::" 점검
# 1-1. 현재 쉘 PATH 확인
CURRENT_PATH=$(run_cmd "[U_14_1] 현재 쉘의 PATH 환경변수 값 확인" "echo \$PATH")
if echo "$CURRENT_PATH" | grep -E '\.:|::|^:|$:' >/dev/null 2>&1; then
    U_14_1=1
    log_basis "[U_14_1] 현재 쉘 PATH 내에 '.' 또는 빈 항목(::)이 포함되어 취약함" "취약"
fi

# 1-2. 공통 설정 파일 내 PATH 점검 (U_14_1 누적 판정)
if [[ $U_14_1 -eq 0 ]]; then
    FILES=("/etc/profile" "/etc/environment")
    for f in "${FILES[@]}"; do
        if [[ -f "$f" ]]; then
            CHECK=$(run_cmd "[U_14_1] $f 파일 내 PATH 설정 점검" "grep -vE '^#|^\s#' '$f' | grep 'PATH=' | grep -E '\.:|::' || echo '양호'")
            if [[ "$CHECK" != "양호" ]]; then
                U_14_1=1
                log_basis "[U_14_1] $f 내 취약한 PATH 설정 발견" "취약"
                break
            fi
        else
            log_step "[U_14_1] 파일 확인" "ls $f" "파일 없음"
        fi
    done
fi

if [[ $U_14_1 -eq 0 ]]; then
    log_basis "[U_14_1] PATH 환경변수에 취약한 설정이 발견되지 않아 양호함" "양호"
fi

IS_VUL=$U_14_1

# --- JSON 출력 (개행 양식 엄수) ---
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
      "U_14_1": $U_14_1
    },
    "timestamp": "$DATE"
  }
}
EOF