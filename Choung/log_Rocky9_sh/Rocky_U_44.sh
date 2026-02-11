#!/bin/bash

# [U-44] tftp, talk 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-44"
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
U_44_1=0; U_44_2=0; U_44_3=0; IS_VUL=0
TARGET_SVCS="tftp|talk|ntalk"

# --- 점검 로직 시작 ---

# 1. [U_44_1] inetd 점검
if [[ -f "/etc/inetd.conf" ]]; then
    I_RES=$(run_cmd "[U_44_1] inetd 설정 확인" "grep -v '^#' /etc/inetd.conf | grep -E '$TARGET_SVCS' || echo '검색 결과 없음'")
    if [[ "$I_RES" != "검색 결과 없음" ]]; then U_44_1=1; fi
else
    log_step "[U_44_1] 파일 확인" "ls /etc/inetd.conf" "파일 없음"
fi
log_basis "[U_44_1] inetd 내 tftp/talk 활성화 여부" "$([[ $U_44_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_44_2] xinetd 점검
if [[ -d "/etc/xinetd.d" ]]; then
    X_RES=$(run_cmd "[U_44_2] xinetd 설정 확인" "grep -rEi 'disable' /etc/xinetd.d/ 2>/dev/null | grep -E '$TARGET_SVCS' | grep -iw 'no' || echo '검색 결과 없음'")
    if [[ "$X_RES" != "검색 결과 없음" ]]; then U_44_2=1; fi
else
    log_step "[U_44_2] 디렉터리 확인" "ls -d /etc/xinetd.d" "디렉터리 없음"
fi
log_basis "[U_44_2] xinetd 내 tftp/talk 활성화 여부" "$([[ $U_44_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [U_44_3] systemd/Process 점검
S_RES=$(run_cmd "[U_44_3] systemd 서비스 활성 확인" "systemctl list-units --type service,socket 2>/dev/null | grep -E '$TARGET_SVCS' | grep -w 'active' || echo '검색 결과 없음'")
if [[ "$S_RES" != "검색 결과 없음" ]]; then
    U_44_3=1
fi

if [[ $U_44_3 -eq 0 ]]; then
    P_RES=$(run_cmd "[U_44_3] 프로세스 실행 확인" "ps -e -o comm | grep -xE 'tftpd|talkd|in.tftpd|in.talkd|in.ntalkd' || echo '검색 결과 없음'")
    if [[ "$P_RES" != "검색 결과 없음" ]]; then U_44_3=1; fi
fi
log_basis "[U_44_3] systemd/프로세스 활성화 여부" "$([[ $U_44_3 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_44_1 -eq 1 || $U_44_2 -eq 1 || $U_44_3 -eq 1 ]]; then IS_VUL=1; fi

# 4. JSON 출력 (양식 유지)
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_44_1": $U_44_1,
      "U_44_2": $U_44_2,
      "U_44_3": $U_44_3
    },
    "timestamp": "$DATE"
  }
}
EOF
