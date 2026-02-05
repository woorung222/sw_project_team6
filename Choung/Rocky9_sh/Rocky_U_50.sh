#!/bin/bash

# [U-50] DNS Zone Transfer 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.121-122
# 자동 조치 가능 유무 : 수동 조치 (named.conf 수정)
# 플래그 설명:
#   U_50_1 : [Service] DNS 서비스(named) 활성화
#   U_50_2 : [Config] allow-transfer { any; } 설정 발견 (취약)
#   U_50_3 : [Config] allow-transfer 설정 누락 (확인 필요)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-50] DNS Zone Transfer 설정 점검 시작"
echo "----------------------------------------------------------------"

# [수정] Root 권한 체크 (설정 파일 읽기 권한 필요)
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} /etc/named.conf 접근을 위해 Root 권한(sudo)으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. [Service] DNS 서비스 활성화 확인 (U_50_1)
if systemctl is-active named >/dev/null 2>&1; then
    VULN_FLAGS+=("U_50_1")
    CONF_FILE="/etc/named.conf"
    
    if [[ -f "$CONF_FILE" ]]; then
        # 2. [Config] allow-transfer 설정 확인 (U_50_2, U_50_3) - PDF p.121
        # 주석 제외하고 'allow-transfer' 구문 검색
        ALLOW_TRANS=$(grep -v "^#" "$CONF_FILE" | grep "allow-transfer")
        
        if [[ -n "$ALLOW_TRANS" ]]; then
            # 설정이 존재하는 경우, 'any'가 있는지 확인
            if [[ "$ALLOW_TRANS" == *"any"* ]]; then
                VULN_STATUS=1
                VULN_FLAGS+=("U_50_2")
                echo -e "${RED}[취약]${NC} Zone Transfer가 전체 허용(any)으로 설정되어 있습니다."
                echo -e "   -> 발견된 설정: $ALLOW_TRANS"
            else
                echo -e "${GREEN}[양호]${NC} Zone Transfer가 제한된 IP로 설정되어 있습니다."
                echo -e "   -> 현재 설정: $ALLOW_TRANS"
            fi
        else
            # 설정이 없는 경우 (U_50_3)
            # 명시적 제한이 없으면 보안상 취약할 수 있음 (가이드라인 기준)
            VULN_STATUS=1
            VULN_FLAGS+=("U_50_3")
            echo -e "${RED}[취약]${NC} 'allow-transfer' 설정이 발견되지 않았습니다. (명시적 제한 필요)"
            echo -e "   -> 조치 권고: allow-transfer { none; }; 또는 { 신뢰된IP; }; 추가"
        fi
    else
        echo -e "${WARN}[정보]${NC} 설정 파일($CONF_FILE)을 찾을 수 없습니다."
    fi

else
    echo -e "${GREEN}[양호]${NC} DNS 서비스(named)가 비활성화되어 있습니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (Zone Transfer 설정이 안전합니다)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
