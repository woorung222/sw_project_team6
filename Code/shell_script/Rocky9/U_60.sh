#!/bin/bash

# [U-60] SNMP Community String 복잡성 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.145
# 점검 목적 : SNMP 커뮤니티 스트링(비밀번호)을 복잡하게 설정하여 추측 공격 방지
# 자동 조치 가능 유무 : 불가능 (관리자가 직접 설정 변경 필요)
# 플래그 설명:
#   U_60_1 : [Config] SNMP Community String이 취약함 (기본값 사용 또는 10자리 미만)

# --- 점검 로직 시작 ---

# 초기화
U_60_1=0

# 1. 패키지 설치 여부 확인
# net-snmp 패키지가 없으면 서비스 불가하므로 양호
if rpm -qa | grep -q "net-snmp"; then
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    if [[ -f "$SNMP_CONF" ]]; then
        # 커뮤니티 스트링 추출
        # 1. com2sec 설정에서 스트링 추출 (4번째 필드)
        STR_COM2SEC=$(grep -v "^#" "$SNMP_CONF" 2>/dev/null | grep "com2sec" | awk '{print $4}')
        
        # 2. rocommunity/rwcommunity 설정에서 스트링 추출 (2번째 필드)
        STR_COMMUNITY=$(grep -v "^#" "$SNMP_CONF" 2>/dev/null | grep -E "^rocommunity|^rwcommunity" | awk '{print $2}')
        
        # 통합
        ALL_STRINGS="$STR_COM2SEC $STR_COMMUNITY"
        
        # 스트링 검사
        for STR in $ALL_STRINGS; do
            # 1) 기본값(public, private) 체크
            if [[ "$STR" == "public" ]] || [[ "$STR" == "private" ]]; then
                U_60_1=1
                break
            fi
            
            # 2) 길이 체크 (10자리 미만이면 취약)
            if [[ ${#STR} -lt 10 ]]; then
                U_60_1=1
                break
            fi
        done
    fi
fi

# 2. 전체 취약 여부 판단
IS_VUL=$U_60_1

# 3. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-60",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service_management",
    "flag": {
      "U_60_1": $U_60_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
