#!/bin/bash

# [U-59] 안전한 SNMP 버전 사용
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.143-144 
# 점검 목적 : 평문 통신을 하는 SNMP v1, v2 사용을 차단하고, 암호화된 v3 사용 유도
# 자동 조치 가능 유무 : 불가능 (설정 파일 편집)
# 플래그 설명:
#   U_59_1 : [Config] SNMP v1/v2c 커뮤니티 설정(rocommunity, rwcommunity, com2sec) 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-59] 안전한 SNMP 버전 사용 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 우선 확인
PKG_CHECK=$(rpm -qa | grep "net-snmp")

if [[ -z "$PKG_CHECK" ]]; then
    echo -e "${GREEN}[양호]${NC} SNMP 서비스 패키지(net-snmp)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 설정 파일 점검
echo -e "${YELLOW}[정보]${NC} SNMP 패키지가 설치되어 있습니다. 설정 파일 버전을 점검합니다."

SNMP_CONF="/etc/snmp/snmpd.conf"

if [[ -f "$SNMP_CONF" ]]; then
    # 3-1. v1/v2c 설정 확인 (rocommunity, rwcommunity, com2sec)
    # 주석(#) 제외하고 검색. 이 설정들이 있으면 v1/v2c가 활성화된 것으로 판단
    V1_V2_CHECK=$(grep -v "^#" "$SNMP_CONF" | grep -E "rocommunity|rwcommunity|com2sec")
    
    if [[ -n "$V1_V2_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_59_1")
        echo -e "${RED}[취약]${NC} [Config] SNMP v1/v2c 관련 설정이 발견되었습니다 (평문 전송 위험)."
        echo -e "   -> 발견된 설정(일부):"
        echo "$V1_V2_CHECK" | head -3 | sed 's/^/      /'
    else
        # v1/v2c 설정이 없으면 안전한 것으로 판단 (v3는 선택사항이지만 v1/v2 제거가 핵심)
        echo -e "${GREEN}[양호]${NC} [Config] 취약한 SNMP v1/v2c 설정이 발견되지 않았습니다."
        
        # 참고용: v3 설정 확인
        V3_CHECK=$(grep -v "^#" "$SNMP_CONF" | grep -E "rouser|rwuser")
        if [[ -n "$V3_CHECK" ]]; then
            echo -e "   -> SNMP v3 설정이 확인되었습니다."
        else
            echo -e "   -> (참고) SNMP v3 설정도 발견되지 않았습니다 (서비스 미구성 상태 가능)."
        fi
    fi
else
    # 패키지는 있으나 설정 파일이 없는 경우
    echo -e "${YELLOW}[정보]${NC} 설정 파일($SNMP_CONF)을 찾을 수 없습니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (v1/v2c 미사용)"
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
