#!/bin/bash

# [U-23] SUID, SGID, Sticky bit 설정 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 주요 불필요 대상 파일(dump, restore, at 등)에 SUID/SGID가 설정된 경우 취약

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-23"
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
U_23_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

CHECK_FILES=(
    "/sbin/dump"
    "/usr/sbin/dump"
    "/sbin/restore"
    "/usr/sbin/restore"
    "/usr/bin/at"
    "/usr/bin/lpq"
    "/usr/bin/lpr"
    "/usr/bin/lprm"
)

# [수정] 모든 파일에 대해 run_cmd 또는 log_step 실행
for FILE in "${CHECK_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        # 파일이 존재하면 권한 확인 명령어를 run_cmd로 실행하여 로그 남김
        # (취약 여부 판단 전 단계에서 무조건 로그 기록)
        CUR_PERM=$(run_cmd "[U_23_1] 파일 권한 점검: $FILE" "stat -c '%a' $FILE")
        
        # SUID(-u) 또는 SGID(-g) 설정 여부 확인
        if [ -u "$FILE" ] || [ -g "$FILE" ]; then
            U_23_1=1
            VULN_DETAILS="$VULN_DETAILS $FILE($CUR_PERM)"
        fi
    else
        # 파일이 없으면 없다고 로그 남김
        log_step "[U_23_1] 파일 설치 여부 확인" "[ -f $FILE ]" "파일 미설치 (양호)"
    fi
done

# --- 전체 결과 집계 ---
IS_VUL=$U_23_1

if [ $U_23_1 -eq 1 ]; then
    log_basis "[U_23_1] 불필요한 SUID/SGID 설정 파일 발견: $VULN_DETAILS" "취약"
else
    log_basis "[U_23_1] 검사 대상 파일들 중 SUID/SGID 설정 파일이 발견되지 않음" "양호"
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-23",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_23_1": $U_23_1
    },
    "timestamp": "$DATE"
  }
}
EOF
