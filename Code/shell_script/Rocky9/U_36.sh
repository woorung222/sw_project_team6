#!/bin/bash

# [U-36] r-command 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.77-79
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_36_1 : [inetd] inetd 설정 내 r-command 활성화 발견
#   U_36_2 : [xinetd] xinetd 설정 내 r-command 활성화 발견
#   U_36_3 : [systemd] r-command 서비스(rlogin, rsh, rexec) 활성화 발견
#   U_36_4 : [Package] r-command 관련 패키지 설치 여부 (rsh-server 등)

# --- 점검 로직 시작 ---

# 초기화 (0: 양호, 1: 취약)
U_36_1=0
U_36_2=0
U_36_3=0
U_36_4=0

# 1. [systemd] 점검 (U_36_3)
if systemctl list-units --type service,socket 2>/dev/null | grep -E "rlogin|rsh|rexec" | grep -w "active" >/dev/null 2>&1; then
    U_36_3=1
fi

# 2. [xinetd] 점검 (U_36_2)
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 설정 확인
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "rlogin|rsh|rexec|shell|login|exec" | grep -iw "no" >/dev/null 2>&1; then
        U_36_2=1
    fi
fi

# 3. [inetd] 점검 (U_36_1)
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석 제외하고 r-command 서비스 설정 확인
    if grep -v "^#" /etc/inetd.conf | grep -iE "rlogin|rsh|rexec|shell|login|exec" >/dev/null 2>&1; then
        U_36_1=1
    fi
fi

# 4. [Package] 점검 (U_36_4)
# rpm -qa 명령어로 패키지 설치 여부 확인
if rpm -qa | grep -E "^rsh|^rlogin|^rexec" >/dev/null 2>&1; then
    U_36_4=1
fi

# 5. 전체 취약 여부 판단 (하나라도 1이면 1)
IS_VUL=0
if [[ $U_36_1 -eq 1 ]] || [[ $U_36_2 -eq 1 ]] || [[ $U_36_3 -eq 1 ]] || [[ $U_36_4 -eq 1 ]]; then
    IS_VUL=1
fi

# 6. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-36",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_36_1": $U_36_1,
      "U_36_2": $U_36_2,
      "U_36_3": $U_36_3,
      "U_36_4": $U_36_4
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
