#!/bin/bash

# [U-52] Telnet 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.124-126
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 패키지 삭제)
# 플래그 설명:
#   U_52_1 : [inetd] /etc/inetd.conf 내 Telnet 활성화 설정 발견
#   U_52_2 : [xinetd] /etc/xinetd.d/telnet 내 disable=yes 미설정
#   U_52_3 : [systemd] telnet.socket 또는 service 활성화 상태
#   U_52_4 : [Process] 실제 Telnet 프로세스 실행 중

# --- 점검 로직 시작 ---

# 초기화
U_52_1=0
U_52_2=0
U_52_3=0
U_52_4=0

# 1. 패키지 설치 여부 확인
# telnet-server 패키지가 설치되어 있어야 서비스 구동 가능 (미설치 시 모두 0/양호)
if rpm -qa | grep -q "telnet-server"; then

    # 2. [inetd] 설정 점검 (U_52_1)
    if [[ -f "/etc/inetd.conf" ]]; then
        # 주석 제외하고 telnet 설정이 있으면 취약
        if grep -v "^#" "/etc/inetd.conf" 2>/dev/null | grep -q "telnet"; then
            U_52_1=1
        fi
    fi

    # 3. [xinetd] 설정 점검 (U_52_2)
    if [[ -f "/etc/xinetd.d/telnet" ]]; then
        # disable = yes 설정이 없으면 취약
        if ! grep "disable" "/etc/xinetd.d/telnet" 2>/dev/null | grep -q "yes"; then
            U_52_2=1
        fi
    fi

    # 4. [systemd] 점검 (U_52_3)
    # socket 또는 service 활성화 여부 확인
    if systemctl is-active telnet.socket >/dev/null 2>&1 || systemctl is-active telnet.service >/dev/null 2>&1; then
        U_52_3=1
    fi

    # 5. [Process] 점검 (U_52_4)
    # 실제 프로세스 실행 여부 확인
    if ps -ef | grep -v grep | grep -q "telnet"; then
        U_52_4=1
    fi
fi

# 6. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_52_1 -eq 1 ]] || [[ $U_52_2 -eq 1 ]] || [[ $U_52_3 -eq 1 ]] || [[ $U_52_4 -eq 1 ]]; then
    IS_VUL=1
fi

# 7. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-52",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_52_1": $U_52_1,
      "U_52_2": $U_52_2,
      "U_52_3": $U_52_3,
      "U_52_4": $U_52_4
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
