#!/bin/bash

# [U-24] 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

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

# 초기화
U_24_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 홈 디렉터리 내 환경변수 파일 점검 (U_24_1)
# 점검 대상 파일 목록
START_FILES=(".profile" ".bash_profile" ".bashrc" ".bash_login")

# 사용자별 홈 디렉터리 및 소유자 추출
mapfile -t USERS < <(awk -F: '$7!="/usr/sbin/nologin" && $7!="/bin/false" && $6!="" {print $1":"$6}' /etc/passwd)

for entry in "${USERS[@]}"; do
    uname="${entry%%:*}"
    uhome="${entry#*:}"
    
    if [[ -d "$uhome" ]]; then
        for f in "${START_FILES[@]}"; do
            target="$uhome/$f"
            if [[ -f "$target" ]]; then
                # 소유자 및 권한 확인 커맨드 기록
                OWNER=$(run_cmd "[U_24_1] $target 소유자 확인" "stat -c '%U' '$target'")
                PERM=$(run_cmd "[U_24_1] $target 권한(other write) 확인" "stat -c '%a' '$target' | grep -E '.[2367]$|^[0-9][2367].$' || echo 'safe'")
                
                # 소유자가 root 또는 해당 사용자여야 함, 타인 쓰기 금지
                if [[ "$OWNER" != "root" && "$OWNER" != "$uname" ]] || [[ "$PERM" != "safe" ]]; then
                    U_24_1=1
                    log_basis "[U_24_1] $target 파일 소유자($OWNER) 또는 권한($PERM) 미흡" "취약"
                fi
            fi
        done
    fi
done

if [[ $U_24_1 -eq 0 ]]; then
    log_basis "[U_24_1] 모든 사용자 환경변수 파일의 소유자 및 권한 설정 양호" "양호"
fi

IS_VUL=$U_24_1

# --- JSON 출력 ---
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
      "U_24_1": $U_24_1
    },
    "timestamp": "$DATE"
  }
}
EOF
