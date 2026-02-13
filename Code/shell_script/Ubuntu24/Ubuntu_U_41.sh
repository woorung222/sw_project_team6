#!/usr/bin/env bash
set -u

# =========================================================
# U_41 (상) 불필요한 automountd 제거 | Ubuntu 24.04
# - 진단 기준: autofs(automountd) 서비스가 활성화되어 있는지 점검
# - Rocky 논리 반영:
#   U_41_1 : 현재 서비스가 실행 중(Active)이거나 프로세스가 존재하는지 확인
#   U_41_2 : 부팅 시 자동 실행(Enabled) 설정되어 있는지 확인
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_41"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_41_1=0
U_41_2=0

# -------------------------
# 1. [U_41_1] 현재 실행 여부 점검
# -------------------------
# systemd 서비스 상태 확인 또는 프로세스(automount, autofs) 확인
if systemctl is-active --quiet autofs 2>/dev/null || \
   ps -ef | grep -v grep | grep -E "automount|autofs" >/dev/null 2>&1; then
    U_41_1=1
fi

# -------------------------
# 2. [U_41_2] 자동 실행 설정 점검
# -------------------------
# systemd 서비스가 enabled 상태인지 확인
if systemctl is-enabled --quiet autofs 2>/dev/null; then
    U_41_2=1
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$U_41_1" -eq 1 ] || [ "$U_41_2" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_41_1": $U_41_1,
      "U_41_2": $U_41_2
    },
    "timestamp": "$DATE"
  }
}
EOF