#!/bin/bash

# [U-41] automountd(autofs) 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-41"
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
U_41_1=0; U_41_2=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_41_1] automountd 프로세스 실행 여부 확인
# grep -v grep 은 기본 포함
PROC_CHECK=$(run_cmd "[U_41_1] automount 프로세스 확인" "ps -ef | grep -iE 'automount|autofs' | grep -v 'grep' || echo 'none'")

if [[ "$PROC_CHECK" != "none" ]]; then
    U_41_1=1
    log_basis "[U_41_1] automount/autofs 프로세스가 실행 중임" "취약"
else
    log_basis "[U_41_1] automount/autofs 프로세스 미실행" "양호"
fi

# 2. [U_41_2] 서비스 활성화 설정 확인 (Systemd & Legacy Init)
# 2-1. Systemd 확인
SYSTEMD_CHECK=$(run_cmd "[U_41_2] systemd autofs 활성화 확인" "systemctl list-unit-files 2>/dev/null | grep -iE 'autofs|automount' | grep 'enabled' || echo 'none'")

# 2-2. Legacy rc.d 확인
if compgen -G "/etc/rc*.d/S*" > /dev/null; then
    RC_CHECK=$(run_cmd "[U_41_2] rc.d autofs 링크 확인" "ls -l /etc/rc*.d/S* 2>/dev/null | grep -E 'amd|autofs' || echo 'none'")
else
    RC_CHECK="none"
    run_cmd "[U_41_2] rc.d 디렉토리 확인" "echo 'Legacy init script directory not found (Skipped)'"
fi

if [[ "$SYSTEMD_CHECK" != "none" ]] || [[ "$RC_CHECK" != "none" ]]; then
    U_41_2=1
    log_basis "[U_41_2] 부팅 시 autofs 자동 실행 설정됨 (Systemd 또는 rc.d)" "취약"
else
    log_basis "[U_41_2] 부팅 시 autofs 자동 실행 설정 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_41_1 -eq 1 || $U_41_2 -eq 1 ]]; then
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
    "category": "service",
    "flag": {
      "U_41_1": $U_41_1,
      "U_41_2": $U_41_2
    },
    "timestamp": "$DATE"
  }
}
EOF
