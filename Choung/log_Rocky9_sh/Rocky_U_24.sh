#!/bin/bash

# [U-24] 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이고, 타 사용자 쓰기 권한이 없는 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-24"
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
U_24_1=0 
IS_VUL=0

# --- 점검 시작 ---

CHECK_FILES=".profile .cshrc .login .kshrc .bash_profile .bashrc .bash_logout .netrc .exrc"

# /etc/passwd 읽기
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    if [ -d "$HOMEDIR" ]; then
        for FILE in $CHECK_FILES; do
            TARGET="$HOMEDIR/$FILE"
            
            # 파일이 존재하는 경우 점검 및 로그 기록
            if [ -f "$TARGET" ]; then
                # 1. 소유자 확인 (run_cmd 사용 -> 모든 파일 로그 남김)
                FILE_OWNER=$(run_cmd "[U_24_1] 소유자 확인: $TARGET" "stat -c '%U' $TARGET")
                
                # 소유자가 root도 아니고, 해당 계정(USERNAME)도 아니면 취약
                if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USERNAME" ]; then
                    U_24_1=1
                fi

                # 2. 권한 확인 (run_cmd 사용)
                PERM_STR=$(run_cmd "[U_24_1] 권한 확인: $TARGET" "stat -c '%A' $TARGET")
                
                # Group Write(5번째), Other Write(8번째) 확인
                if [ "${PERM_STR:5:1}" == "w" ] || [ "${PERM_STR:8:1}" == "w" ]; then
                    U_24_1=1
                fi
            fi
        done
    fi
done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_24_1

if [ $U_24_1 -eq 1 ]; then
    log_basis "[U_24_1] 소유자 또는 권한 설정이 미흡한 환경변수 파일이 발견됨" "취약"
else
    log_basis "[U_24_1] 모든 환경변수 파일의 소유자 및 권한 설정이 양호함" "양호"
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
    "flag_id": "U-24",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_24_1": $U_24_1
    },
    "timestamp": "$DATE"
  }
}
EOF
