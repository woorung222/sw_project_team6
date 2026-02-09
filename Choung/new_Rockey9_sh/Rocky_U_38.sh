#!/bin/bash

# [U-38] DoS 공격에 취약한 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.83-85
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 비활성화)
# 플래그 설명:
#   U_38_1 : [inetd] inetd 설정 내 해당 서비스 활성화 발견
#   U_38_2 : [xinetd] xinetd 설정 내 해당 서비스 활성화 발견
#   U_38_3 : [systemd] echo, discard, daytime, chargen 서비스 활성화 발견
#   U_38_4 : [Port] 포트(7, 9, 13, 19, 123, 161, 53, 25) 오픈 여부

# --- 점검 로직 시작 ---

# 초기화
U_38_1=0
U_38_2=0
U_38_3=0
U_38_4=0

# 점검 대상 서비스 정규식
DOS_SVCS="echo|discard|daytime|chargen"

# 1. [systemd] 점검 (U_38_3)
if systemctl list-units --type service,socket 2>/dev/null | grep -E "$DOS_SVCS" | grep -w "active" >/dev/null 2>&1; then
    U_38_3=1
fi

# 2. [xinetd] 점검 (U_38_2)
if [[ -d "/etc/xinetd.d" ]]; then
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$DOS_SVCS" | grep -iw "no" >/dev/null 2>&1; then
        U_38_2=1
    fi
fi

# 3. [inetd] 점검 (U_38_1)
if [[ -f "/etc/inetd.conf" ]]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "$DOS_SVCS" >/dev/null 2>&1; then
        U_38_1=1
    fi
fi

# 4. [Port] 포트 점검 (U_38_4)
# 점검 대상 포트: 7, 9, 13, 19, 25, 53, 123, 161
if ss -tuln | awk '{print $5}' | grep -E ":(7|9|13|19|25|53|123|161)$" >/dev/null 2>&1; then
    U_38_4=1
fi

# 5. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_38_1 -eq 1 ]] || [[ $U_38_2 -eq 1 ]] || [[ $U_38_3 -eq 1 ]] || [[ $U_38_4 -eq 1 ]]; then
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
    "flag_id": "U-38",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_38_1": $U_38_1,
      "U_38_2": $U_38_2,
      "U_38_3": $U_38_3,
      "U_38_4": $U_38_4
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
