#!/bin/bash

# [U-27] R-commands 서비스 관련 파일(/etc/hosts.equiv, .rhosts) 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/hosts.equiv 및 $HOME/.rhosts 파일의 소유자가 root 또는 해당 계정이고, 권한이 600 이하이며, '+' 설정이 없으면 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-27"
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
U_27_1=0 
IS_VUL=0

# --- 점검 시작 ---

# 1. /etc/hosts.equiv 점검
HOSTS_EQUIV="/etc/hosts.equiv"

if [ -f "$HOSTS_EQUIV" ]; then
    OWNER=$(run_cmd "[U_27_1] hosts.equiv 소유자 확인" "stat -c '%U' $HOSTS_EQUIV")
    PERM=$(run_cmd "[U_27_1] hosts.equiv 권한 확인" "stat -c '%a' $HOSTS_EQUIV")
    PLUS_CHECK=$(run_cmd "[U_27_1] hosts.equiv '+' 설정 확인" "grep -E '^\+' $HOSTS_EQUIV")

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ] || [ -n "$PLUS_CHECK" ]; then
        U_27_1=1
    fi
else
    # [수정] 파일이 없으면 없다고 로그 남기기
    log_step "[U_27_1] hosts.equiv 존재 여부" "[ -f $HOSTS_EQUIV ]" "파일 없음 (양호)"
fi

# 2. $HOME/.rhosts 점검
# 사용자가 많으면 로그가 길어지지만, 요청하신 대로 수행 내용을 다 남깁니다.
while IFS=: read -r user _ uid _ _ home _; do
    if [[ "$uid" -ge 1000 || "$uid" -eq 0 ]]; then
        RHOSTS="$home/.rhosts"
        
        if [ -f "$RHOSTS" ]; then
             f_owner=$(run_cmd "[U_27_1] $RHOSTS 소유자 확인" "stat -c '%U' $RHOSTS")
             f_perm=$(run_cmd "[U_27_1] $RHOSTS 권한 확인" "stat -c '%a' $RHOSTS")
             f_plus=$(run_cmd "[U_27_1] $RHOSTS '+' 설정 확인" "grep -E '^\+' $RHOSTS")
             
             if [[ "$f_owner" != "root" && "$f_owner" != "$user" ]] || \
                [[ "$f_perm" -gt 600 ]] || \
                [[ -n "$f_plus" ]]; then
                 U_27_1=1
             fi
        # [수정] 파일이 없는 경우에도 로그 남기기 (너무 많으면 주석 처리 가능)
        # else
        #     log_step "[U_27_1] .rhosts 확인($user)" "[ -f $RHOSTS ]" "파일 없음"
        fi
    fi
done < /etc/passwd

# --- 전체 결과 집계 ---
if [ $U_27_1 -eq 1 ]; then
    IS_VUL=1
    log_basis "[U_27_1] R-command 관련 파일 설정 취약" "취약"
else
    IS_VUL=0
    log_basis "[U_27_1] R-command 관련 파일이 없거나 설정 양호" "양호"
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
    "flag_id": "U-27",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_27_1": $U_27_1
    },
    "timestamp": "$DATE"
  }
}
EOF