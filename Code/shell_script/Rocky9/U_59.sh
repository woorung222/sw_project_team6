#!/bin/bash

# [U-59] 안전한 SNMP 버전 사용
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.143-144
# 점검 목적 : 평문 통신을 하는 SNMP v1, v2 사용을 차단하고, 암호화된 v3 사용 유도
# 자동 조치 가능 유무 : 불가능 (설정 파일 편집)
# 플래그 설명:
#   U_59_1 : [Config] SNMP v1/v2c 커뮤니티 설정(rocommunity, rwcommunity, com2sec) 발견

# --- 점검 로직 시작 ---

# 초기화
U_59_1=0

# 1. 패키지 설치 여부 확인
# net-snmp 패키지가 없으면 서비스 불가하므로 양호
if rpm -qa | grep -q "net-snmp"; then
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    # 2. 설정 파일 점검 (U_59_1)
    if [[ -f "$SNMP_CONF" ]]; then
        # v1/v2c 활성화 지시어 확인 (주석 제외)
        # rocommunity, rwcommunity, com2sec 설정이 있으면 취약
        if grep -v "^#" "$SNMP_CONF" 2>/dev/null | grep -E "rocommunity|rwcommunity|com2sec" >/dev/null 2>&1; then
            U_59_1=1
        fi
    else
        # 패키지는 있으나 설정 파일이 없는 경우 (특이 케이스)
        # 설정이 없으므로 기능이 동작하지 않아 안전할 수 있으나, 관리적 측면에서 확인 필요.
        # 로직상 취약점(설정 발견)이 없으므로 0 유지.
        :
    fi
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_59_1

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-59",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_59_1": $U_59_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
