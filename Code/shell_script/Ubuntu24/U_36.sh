#!/usr/bin/env bash
set -u

# =========================================================
# U_36 (상) r-command 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: r-command(rsh, rlogin, rexec) 서비스 활성화 및 패키지 설치 여부
# - Rocky 논리 반영:
#   U_36_1: inetd.conf 내 r-command 설정
#   U_36_2: xinetd.d 내 r-command 설정
#   U_36_3: systemd 서비스 Active 여부 (Rocky 기준 통일)
#   U_36_4: 관련 패키지 설치 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_36"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_36_1=0
U_36_2=0
U_36_3=0
U_36_4=0

# -------------------------
# 1. [inetd] 점검 (U_36_1)
# -------------------------
if [ -f "/etc/inetd.conf" ]; then
    # rlogin, rsh, rexec, shell, login, exec 서비스 확인
    if grep -v "^#" /etc/inetd.conf | grep -E "^\s*(rlogin|rsh|rexec|shell|login|exec)\s+" >/dev/null 2>&1; then
        U_36_1=1
    fi
fi

# -------------------------
# 2. [xinetd] 점검 (U_36_2)
# -------------------------
if [ -d "/etc/xinetd.d" ]; then
    # r-command 관련 파일에서 disable = no 인지 확인
    # grep -r 로 디렉터리 전체 검색
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "rlogin|rsh|rexec|shell|login|exec" | grep -iw "no" >/dev/null 2>&1; then
        U_36_2=1
    fi
fi

# -------------------------
# 3. [systemd] 점검 (U_36_3)
# -------------------------
# Rocky 기준: 현재 실행 중(Active)인 서비스 확인
# rsh.socket, rlogin.socket, rexec.socket 및 service 확인
if systemctl is-active --quiet rsh.socket rlogin.socket rexec.socket \
   rsh.service rlogin.service rexec.service 2>/dev/null; then
    U_36_3=1
fi

# -------------------------
# 4. [Package] 점검 (U_36_4)
# -------------------------
# Ansible/Rocky 기준 패키지 목록
# Ubuntu는 rsh-client, rsh-server 등으로 나뉨
PACKAGES="rsh-server rsh-client rlogin rexec rsh-redone-server rsh-redone-client"

# dpkg -l 로 설치된(ii) 패키지 확인
INSTALLED=$(dpkg -l $PACKAGES 2>/dev/null | grep "^ii" | awk '{print $2}')

if [ -n "$INSTALLED" ]; then
    U_36_4=1
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$U_36_1" -eq 1 ] || [ "$U_36_2" -eq 1 ] || [ "$U_36_3" -eq 1 ] || [ "$U_36_4" -eq 1 ]; then
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
      "U_36_1": $U_36_1,
      "U_36_2": $U_36_2,
      "U_36_3": $U_36_3,
      "U_36_4": $U_36_4
    },
    "timestamp": "$DATE"
  }
}
EOF