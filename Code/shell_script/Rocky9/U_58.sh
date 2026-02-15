#!/bin/bash

# [U-58] 불필요한 SNMP 서비스 구동 점검
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.141-142
# 점검 목적 : 불필요한 SNMP 서비스를 비활성화하여 시스템 중요 정보 유출 및 불법 수정 방지
# 자동 조치 가능 유무 : 가능 (서비스 중지)
# 플래그 설명:
#   U_58_1 : [Service] SNMP 서비스(snmpd) 활성화 또는 프로세스 실행 중 (취약)

# --- 점검 로직 시작 ---

# 초기화
U_58_1=0

# 1. SNMP 서비스 활성화 여부 점검 (U_58_1)
# systemd 서비스 상태 확인
if systemctl is-active snmpd >/dev/null 2>&1; then
    U_58_1=1
fi

# 2. 프로세스 실행 여부 확인 (서비스 데몬이 아닌 수동 실행 등 포함)
# ps 명령어로 snmpd 프로세스가 떠 있는지 재확인
if [[ $U_58_1 -eq 0 ]]; then
    if ps -ef | grep -v grep | grep -q "snmpd"; then
        U_58_1=1
    fi
fi

# 3. 전체 취약 여부 판단
# 서비스가 켜져 있거나 프로세스가 돌고 있으면 취약
IS_VUL=$U_58_1

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-58",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_58_1": $U_58_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
