#!/bin/bash

# [U-38] DoS 공격에 취약한 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-38"
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
U_38_1=0; U_38_2=0; U_38_3=0; U_38_4=0; IS_VUL=0
DOS_SVCS="echo|discard|daytime|chargen"

# 1. [U_38_1] inetd 점검
if [[ -f "/etc/inetd.conf" ]]; then
    I_RES=$(run_cmd "[U_38_1] inetd DoS 서비스 확인" "grep -v '^#' /etc/inetd.conf | grep -E '$DOS_SVCS'")
    if [[ -n "$I_RES" ]]; then U_38_1=1; fi
else
    log_step "[U_38_1] 파일 확인" "ls /etc/inetd.conf" "파일 없음"
fi
log_basis "[U_38_1] inetd 내 DoS 서비스 활성화 여부" "$([[ $U_38_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_38_2] xinetd 점검
if [[ -d "/etc/xinetd.d" ]]; then
    X_RES=$(run_cmd "[U_38_2] xinetd DoS 서비스 확인" "grep -rEi 'disable' /etc/xinetd.d/ 2>/dev/null | grep -E '$DOS_SVCS' | grep -iw 'no'")
    if [[ -n "$X_RES" ]]; then U_38_2=1; fi
else
    log_step "[U_38_2] 디렉터리 확인" "ls -d /etc/xinetd.d" "디렉터리 없음"
fi
log_basis "[U_38_2] xinetd 내 DoS 서비스 활성화 여부" "$([[ $U_38_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [U_38_3] systemd 점검
S_RES=$(run_cmd "[U_38_3] systemd DoS 서비스 확인" "systemctl list-units --type service,socket 2>/dev/null | grep -E '$DOS_SVCS' | grep -w 'active'")
if [[ -n "$S_RES" ]]; then U_38_3=1; fi
log_basis "[U_38_3] systemd DoS 서비스 활성화 여부" "$([[ $U_38_3 -eq 1 ]] && echo '취약' || echo '양호')"

# 4. [U_38_4] Port 점검
P_RES=$(run_cmd "[U_38_4] 주요 DoS 포트 Listen 확인" "ss -tuln | awk '{print \$5}' | grep -E ':(7|9|13|19|25|53|123|161)$'")
if [[ -n "$P_RES" ]]; then U_38_4=1; fi
log_basis "[U_38_4] 주요 DoS 포트 오픈 여부" "$([[ $U_38_4 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_38_1 -eq 1 ]] || [[ $U_38_2 -eq 1 ]] || [[ $U_38_3 -eq 1 ]] || [[ $U_38_4 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_38_1": $U_38_1,
      "U_38_2": $U_38_2,
      "U_38_3": $U_38_3,
      "U_38_4": $U_38_4
    },
    "timestamp": "$DATE"
  }
}
EOF