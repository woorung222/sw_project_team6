#!/bin/bash

# [U-61] SNMP 서비스 접근 통제
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.146-147
# 점검 목적 : SNMP 서비스 접속 시 허용 대상을 특정 호스트로 제한(Access Control)하고 있는지 확인
# 자동 조치 가능 유무 : 불가능 (관리자 IP 및 네트워크 환경에 맞게 수동 설정 필요)
# 플래그 설명:
#   U_61_1 : [com2sec] 접근 제어(Source)가 default 또는 0.0.0.0으로 설정되어 전체 허용됨

# --- 점검 로직 시작 ---

# 초기화
U_61_1=0

# 1. 패키지 설치 여부 정밀 확인
# net-snmp 데몬 패키지가 설치되어 있어야 함 (libs, utils 등 제외)
if rpm -qa | grep -qE "^net-snmp-[0-9]"; then
    
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    # 2. com2sec 설정 점검 (U_61_1)
    if [[ -f "$SNMP_CONF" ]]; then
        # 주석 제외하고 com2sec 라인 확인
        # 구문: com2sec <NAME> <SOURCE> <COMMUNITY>
        # awk $3 (Source)가 'default' 또는 '0.0.0.0' 인지 확인
        
        WEAK_CONFIG=$(grep -v "^#" "$SNMP_CONF" 2>/dev/null | grep "com2sec" | awk '$3 == "default" || $3 == "0.0.0.0"')
        
        if [[ -n "$WEAK_CONFIG" ]]; then
            U_61_1=1
        fi
    fi
    # 패키지는 있으나 설정 파일이 없는 경우, 기본적으로 동작하지 않거나 기본값이 적용될 수 있음.
    # 접근 통제 설정이 "발견되지 않음"으로 볼 수도 있으나, 
    # 명시적인 취약 설정(default/0.0.0.0)이 없으므로 로직상 0 유지.
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_61_1

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-61",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service_management",
    "flag": {
      "U_61_1": $U_61_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
