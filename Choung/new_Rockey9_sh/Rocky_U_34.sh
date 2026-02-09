#!/bin/bash

# [U-34] Finger 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.68
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_34_1 : [inetd] /etc/inetd.conf 내 finger 설정 활성화 발견
#   U_34_2 : [xinetd] /etc/xinetd.d/finger 내 활성화 설정 발견
#   U_34_3 : [systemd/Process] Finger 서비스 또는 프로세스 활성화 발견

# --- 점검 로직 시작 ---

# 초기화 (0: 양호, 1: 취약)
U_34_1=0
U_34_2=0
U_34_3=0

# 1. [inetd] 설정 점검 (U_34_1)
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석(#)을 제외하고 finger 서비스가 포함된 행이 있는지 확인
    if grep -v "^#" /etc/inetd.conf | grep -iw "finger" >/dev/null 2>&1; then
        U_34_1=1
    fi
fi

# 2. [xinetd] 설정 점검 (U_34_2)
if [[ -f "/etc/xinetd.d/finger" ]]; then
    # disable 옵션이 'no'인 경우 취약
    if grep -i "disable" /etc/xinetd.d/finger | grep -iw "no" >/dev/null 2>&1; then
        U_34_2=1
    fi
fi

# 3. [systemd/Process] 점검 (U_34_3)
# systemd 서비스 활성화 여부 확인
CHECK_SYSTEMD=$(systemctl is-active finger.socket finger.service 2>/dev/null | grep -w "active")
# 프로세스 실행 여부 확인
CHECK_PROC=$(ps -e -o comm | grep -v "grep" | grep -xw "fingerd")

if [[ -n "$CHECK_SYSTEMD" ]] || [[ -n "$CHECK_PROC" ]]; then
    U_34_3=1
fi

# 4. 전체 취약 여부 판단 (하나라도 1이면 1)
IS_VUL=0
if [[ $U_34_1 -eq 1 ]] || [[ $U_34_2 -eq 1 ]] || [[ $U_34_3 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-34",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_34_1": $U_34_1,
      "U_34_2": $U_34_2,
      "U_34_3": $U_34_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
