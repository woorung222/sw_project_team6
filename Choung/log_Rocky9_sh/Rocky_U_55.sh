#!/bin/bash

# [U-55] FTP 계정 shell 제한
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-55"
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
U_55_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. ftp 계정 존재 여부 및 쉘 설정 확인 (U_55_1)
# 실제 커맨드 실행 기록을 남기기 위해 run_cmd 사용
FTP_ENTRY=$(run_cmd "[U_55_1] /etc/passwd 내 ftp 계정 쉘 설정 확인" "grep '^ftp:' /etc/passwd || echo '안 깔려 있음'")

if [[ "$FTP_ENTRY" != "안 깔려 있음" ]]; then
    # 쉘 필드 추출
    USER_SHELL=$(echo "$FTP_ENTRY" | awk -F: '{print $7}')

    # 로그인 불가 쉘 목록 비교 (/bin/false, /sbin/nologin, /usr/sbin/nologin)
    if [[ "$USER_SHELL" != "/bin/false" ]] && \
       [[ "$USER_SHELL" != "/sbin/nologin" ]] && \
       [[ "$USER_SHELL" != "/usr/sbin/nologin" ]]; then
        U_55_1=1
        log_basis "[U_55_1] ftp 계정에 로그인 가능한 쉘($USER_SHELL)이 설정되어 취약함" "취약"
    else
        log_basis "[U_55_1] ftp 계정에 로그인 불가 쉘($USER_SHELL)이 적절히 설정되어 양호함" "양호"
    fi
else
    # 계정이 없을 경우의 명시적 로깅
    log_basis "[U_55_1] 시스템에 ftp 계정이 존재하지 않음 (안 깔려 있음)" "양호"
fi

# 4. 전체 취약 여부 판단
IS_VUL=$U_55_1

# 5. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-55",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_55_1": $U_55_1
    },
    "timestamp": "$DATE"
  }
}
EOF
