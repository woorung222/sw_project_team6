#!/bin/bash

# [U-60] SNMP Community String 복잡성 설정
# 대상 운영체제 : Rocky Linux 9
# [cite_start]가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.145 [cite: 1624-1675]
# 점검 목적 : SNMP 커뮤니티 스트링(비밀번호)을 복잡하게 설정하여 추측 공격 방지
# 자동 조치 가능 유무 : 불가능 (관리자가 직접 복잡한 문자열로 설정 변경 필요)
# 플래그 설명:
#   U_60_1 : [Config] SNMP Community String이 취약함 (기본값 사용 또는 복잡성 미흡 -> 변경 필요)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-60] SNMP Community String 복잡성 설정 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 확인
PKG_CHECK=$(rpm -qa | grep "net-snmp")

if [[ -z "$PKG_CHECK" ]]; then
    echo -e "${GREEN}[양호]${NC} SNMP 서비스 패키지(net-snmp)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 설정 파일 분석
echo -e "${YELLOW}[정보]${NC} SNMP 패키지가 설치되어 있습니다. 커뮤니티 스트링 복잡성을 점검합니다."

SNMP_CONF="/etc/snmp/snmpd.conf"

if [[ -f "$SNMP_CONF" ]]; then
    # 커뮤니티 스트링 추출 (rocommunity, rwcommunity, com2sec)
    # 1. com2sec 설정에서 스트링 추출 (4번째 필드)
    STRINGS=$(grep -v "^#" "$SNMP_CONF" | grep "com2sec" | awk '{print $4}')
    
    # 2. rocommunity/rwcommunity 설정에서 스트링 추출 (2번째 필드)
    STRINGS_RO=$(grep -v "^#" "$SNMP_CONF" | grep -E "^rocommunity|^rwcommunity" | awk '{print $2}')
    
    # 통합
    ALL_STRINGS="$STRINGS $STRINGS_RO"
    
    # 스트링이 하나라도 발견되었는지 확인
    if [[ -z "$ALL_STRINGS" || "$ALL_STRINGS" =~ ^[[:space:]]*$ ]]; then
         echo -e "${GREEN}[양호]${NC} [Config] 커뮤니티 스트링 설정이 발견되지 않았습니다 (v3 사용 또는 미설정)."
    else
        for STR in $ALL_STRINGS; do
            LEN=${#STR}
            # 통합 점검 로직: 기본값(public, private) 이거나 길이가 짧은 경우(10자리 미만)
            if [[ "$STR" == "public" ]] || [[ "$STR" == "private" ]] || [[ $LEN -lt 10 ]]; then
                VULN_STATUS=1
                # 플래그 중복 방지
                if [[ ! "${VULN_FLAGS[*]}" =~ "U_60_1" ]]; then
                    VULN_FLAGS+=("U_60_1")
                fi
                
                if [[ "$STR" == "public" ]] || [[ "$STR" == "private" ]]; then
                    echo -e "${RED}[취약]${NC} [Config] 기본 커뮤니티 스트링('$STR')이 사용 중입니다."
                else
                    echo -e "${RED}[취약]${NC} [Config] 커뮤니티 스트링('$STR')의 복잡성이 미흡합니다. ($LEN자리)"
                fi
            fi
        done
        
        if [[ $VULN_STATUS -eq 0 ]]; then
             echo -e "${GREEN}[양호]${NC} 모든 커뮤니티 스트링이 복잡성 기준(10자리 이상 등)을 만족합니다."
        else
             echo -e "${RED}[경고]${NC} 보안을 위해 커뮤니티 스트링(비밀번호)을 즉시 변경하십시오."
        fi
    fi

else
    echo -e "${YELLOW}[정보]${NC} 설정 파일($SNMP_CONF)을 찾을 수 없습니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (비밀번호 안전)"
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
