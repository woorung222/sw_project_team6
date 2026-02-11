#!/bin/bash

# [U-10] 동일한 UID 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/passwd 파일 내 동일한 UID를 사용하는 계정이 존재하면 취약

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-10"
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

# 초기 상태 설정
U_10_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

# 1. /etc/passwd에서 UID(3번째 필드) 추출 -> 정렬 -> 중복된 값만 출력(uniq -d)
CMD="cut -d: -f3 /etc/passwd | sort | uniq -d"
DUPLICATE_UIDS=$(run_cmd "[U_10_1] 중복 UID 검사" "$CMD")

if [ -z "$DUPLICATE_UIDS" ]; then
    # 중복된 UID가 없음 (양호)
    U_10_1=0
    log_basis "[U_10_1] 동일한 UID를 사용하는 계정이 존재하지 않음" "양호"
else
    # 중복된 UID가 존재함 (취약)
    U_10_1=1
    # 로그 보기 좋게 한 줄로 변환
    DUPS_INLINE=$(echo "$DUPLICATE_UIDS" | tr '\n' ',' | sed 's/,$//')
    log_basis "[U_10_1] 중복된 UID가 발견됨: $DUPS_INLINE" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_10_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-10",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "account",
    "flag": {
      "U_10_1": $U_10_1
    },
    "timestamp": "$DATE"
  }
}
EOF
