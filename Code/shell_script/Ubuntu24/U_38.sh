#!/usr/bin/env bash
set -u

# =========================================================
# U_38 (상) DoS 공격에 취약한 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: Simple TCP/UDP Services(echo, discard, daytime, chargen) 비활성화 여부
# - Rocky 논리 반영:
#   U_38_1: inetd.conf 설정
#   U_38_2: xinetd.d 설정
#   U_38_3: systemd 서비스 Active 여부 (필수 서비스인 NTP/SMTP 등은 제외하고 순수 DoS 서비스만 점검)
#   U_38_4: 관련 포트 오픈 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_38"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_38_1=0
U_38_2=0
U_38_3=0
U_38_4=0

# 점검 대상 서비스 (Rocky/Ansible 기준 통일)
# NTP, DNS, SMTP 등은 U-38의 주 타겟(Simple Services)이 아니므로 제외
DOS_SERVICES="echo|discard|daytime|chargen"

# -------------------------
# 1. [inetd] 점검 (U_38_1)
# -------------------------
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf | grep -E "^\s*($DOS_SERVICES)\s+" >/dev/null 2>&1; then
        U_38_1=1
    fi
fi

# -------------------------
# 2. [xinetd] 점검 (U_38_2)
# -------------------------
if [ -d "/etc/xinetd.d" ]; then
    # disable = no 인 항목 중 대상 서비스가 있는지 확인
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$DOS_SERVICES" | grep -iw "no" >/dev/null 2>&1; then
        U_38_2=1
    fi
fi

# -------------------------
# 3. [systemd] 점검 (U_38_3)
# -------------------------
# Rocky 기준과 동일하게 'Active' 상태 확인 (실제 떠있는지)
# echo-dgram, echo-stream 등 변형 이름도 포함될 수 있으므로 포괄 검색
# 단, 명확하게 echo, discard, daytime, chargen 이 포함된 유닛만.
if systemctl list-units --type service,socket --state=active 2>/dev/null | grep -E "($DOS_SERVICES)" >/dev/null 2>&1; then
    U_38_3=1
fi

# -------------------------
# 4. [Port] 점검 (U_38_4)
# -------------------------
# 포트: 7(echo), 9(discard), 13(daytime), 19(chargen)
# 추가: 123(ntp), 161(snmp), 53(dns), 25(smtp) -> 가이드상 확인용으로 남겨둠
DOS_PORTS_REGEX=":7 |:9 |:13 |:19 |:123 |:161 |:53 |:25 "

if ss -tuln | grep -E "$DOS_PORTS_REGEX" >/dev/null 2>&1; then
    # 포트가 열려있으면 1 (단, U_38_4는 참고용 성격이 강함)
    U_38_4=1
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
# U_38_4(포트)는 단순 오픈 여부이므로, 실제 취약 여부는 1,2,3(서비스 설정) 위주로 판단하거나
# 가이드 기준에 따라 4번도 포함. 여기서는 모두 포함.
if [ "$U_38_1" -eq 1 ] || [ "$U_38_2" -eq 1 ] || [ "$U_38_3" -eq 1 ] || [ "$U_38_4" -eq 1 ]; then
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
      "U_38_1": $U_38_1,
      "U_38_2": $U_38_2,
      "U_38_3": $U_38_3,
      "U_38_4": $U_38_4
    },
    "timestamp": "$DATE"
  }
}
EOF