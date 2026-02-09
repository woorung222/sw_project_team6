#!/bin/bash

# [U-61] SNMP 서비스 접근 통제
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.146-147
# 점검 목적 : SNMP 서비스 접속 시 허용 대상을 특정 호스트로 제한(Access Control)하고 있는지 확인
# 자동 조치 가능 유무 : 불가능 (관리자 IP 및 네트워크 환경에 맞게 수동 설정 필요)
# 플래그 설명:
#   U_61_1 : [com2sec] 접근 제어(Source)가 default 또는 0.0.0.0으로 설정되어 전체 허용됨

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-61] SNMP 서비스 접근 통제 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 정밀 확인 (Bug Fix)
# net-snmp-libs, net-snmp-utils 등이 아닌 'net-snmp' 데몬 패키지만 정확히 식별
# 정규식: 줄 시작(^) + net-snmp + 하이픈 + 숫자([0-9])
PKG_CHECK=$(rpm -qa | grep -E "^net-snmp-[0-9]")

if [[ -z "$PKG_CHECK" ]]; then
    echo -e "${GREEN}[양호]${NC} SNMP 서비스 패키지(net-snmp)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 설정 파일 분석
echo -e "${YELLOW}[정보]${NC} SNMP 데몬 패키지가 확인되었습니다. com2sec 접근 통제 설정을 점검합니다."
echo -e "   -> 감지된 패키지: $PKG_CHECK"

SNMP_CONF="/etc/snmp/snmpd.conf"

if [[ -f "$SNMP_CONF" ]]; then
    
    # ----------------------------------------------------------------
    # com2sec 설정 점검 (Flag: U_61_1)
    # 형식: com2sec <NAME> <SOURCE> <COMMUNITY>
    # <SOURCE> 필드가 'default'이거나 '0.0.0.0'이면 취약
    # ----------------------------------------------------------------
    
    # 주석 제외하고 com2sec 라인 추출
    COM2SEC_LINES=$(grep -v "^#" "$SNMP_CONF" | grep "com2sec")
    
    if [[ -n "$COM2SEC_LINES" ]]; then
        # awk로 3번째 필드(SOURCE) 확인
        # (표준적으로: com2sec, 이름, 소스, 커뮤니티 순서 -> $3이 소스)
        WEAK_COM2SEC=$(echo "$COM2SEC_LINES" | awk '$3 == "default" || $3 == "0.0.0.0" {print $0}')
        
        if [[ -n "$WEAK_COM2SEC" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_61_1")
            echo -e "${RED}[취약]${NC} [com2sec] 모든 호스트 접속 허용(default/0.0.0.0) 설정이 발견되었습니다."
            echo -e "   -> 설정 내용:\n$WEAK_COM2SEC"
        else
             echo -e "${GREEN}[양호]${NC} [com2sec] default 또는 0.0.0.0 설정이 발견되지 않았습니다."
        fi
    else
        # com2sec 설정 자체가 없는 경우 (v3 전용이거나 설정 없음)
        echo -e "${GREEN}[양호]${NC} [com2sec] 설정이 존재하지 않습니다."
    fi

else
    echo -e "${YELLOW}[정보]${NC} 설정 파일($SNMP_CONF)을 찾을 수 없습니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (접근 통제 설정 적절)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 5. 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
