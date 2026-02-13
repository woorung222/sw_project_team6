#!/usr/bin/env bash
set -u

# =========================================================
# U_34 (상) Finger 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: Finger 서비스가 활성화되어 있는지 점검
# - Rocky 논리 반영:
#   U_34_1: /etc/inetd.conf 내 finger 활성화 여부
#   U_34_2: /etc/xinetd.d/finger 내 disable = no 여부
#   U_34_3: systemd 서비스(finger.socket/service) 또는 프로세스 활성화 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_34"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
FLAG_U_34_1=0
FLAG_U_34_2=0
FLAG_U_34_3=0

# -------------------------
# 1) [U_34_1] inetd.conf 점검
# -------------------------
if [ -f "/etc/inetd.conf" ]; then
    # 주석(#) 제외하고 finger 문자열이 있는지 확인
    if grep -v "^#" /etc/inetd.conf | grep -qw "finger"; then
        FLAG_U_34_1=1
    fi
fi

# -------------------------
# 2) [U_34_2] xinetd.d 점검
# -------------------------
if [ -f "/etc/xinetd.d/finger" ]; then
    # disable = yes 가 설정되어 있지 않으면 취약으로 간주
    # (또는 disable = no 가 있으면 취약)
    if grep -v "^#" /etc/xinetd.d/finger | grep "disable" | grep -qw "no"; then
        FLAG_U_34_2=1
    fi
fi

# -------------------------
# 3) [U_34_3] systemd 및 프로세스 점검
# -------------------------
# 3-1. systemd 서비스 상태 확인 (Rocky와 통일)
# finger.socket 또는 finger.service가 active 상태인지 확인
if systemctl is-active --quiet finger.socket 2>/dev/null || \
   systemctl is-active --quiet finger.service 2>/dev/null; then
    FLAG_U_34_3=1
fi

# 3-2. 프로세스 및 포트 확인 (보조 확인)
# systemd로 관리되지 않는 경우를 대비해 프로세스와 포트도 확인
if [ "$FLAG_U_34_3" -eq 0 ]; then
    if ps -ef | grep -E "finger-server|in.fingerd" | grep -v grep >/dev/null; then
        FLAG_U_34_3=1
    fi
    # 포트 79 (finger) 리스닝 확인
    if ss -tuln | grep -qw ":79"; then
        FLAG_U_34_3=1
    fi
fi

# -------------------------
# 4) VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_34_1" -eq 1 ] || [ "$FLAG_U_34_2" -eq 1 ] || [ "$FLAG_U_34_3" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# 5) Output (JSON)
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
      "U_34_1": $FLAG_U_34_1,
      "U_34_2": $FLAG_U_34_2,
      "U_34_3": $FLAG_U_34_3
    },
    "timestamp": "$DATE"
  }
}
EOF