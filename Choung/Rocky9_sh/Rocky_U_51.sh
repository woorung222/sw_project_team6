#!/bin/bash

# [U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.122-123 [cite: 1152-1173]
# 점검 목적 : DNS 동적 업데이트를 제한하여 레코드 변조 방지
# 자동 조치 가능 유무 : 불가능
# 플래그 설명:
#   U_51_1 : [Service] DNS 서비스 활성화
#   U_51_2 : [Config] allow-update { any; } 설정 발견 (취약)
#   U_51_3 : [Config] allow-update 설정 누락 (명시적 설정 필요)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지 점검 시작"
echo "----------------------------------------------------------------"

# Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} /etc/named.conf 접근을 위해 Root 권한(sudo)으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. [Service] DNS 서비스 활성화 확인 (U_51_1)
if systemctl is-active named >/dev/null 2>&1; then
    VULN_FLAGS+=("U_51_1")
    CONF_FILE="/etc/named.conf"
    
    if [[ -f "$CONF_FILE" ]]; then
        # 2. [Config] allow-update 설정 확인 (U_51_2, U_51_3) - 
        # 주석 제외하고 'allow-update' 구문 검색
        # 정규식: allow-update 이후 { ... } 블록 내용을 확인
        UPDATE_CONF=$(grep -v "^#" "$CONF_FILE" | grep "allow-update")
        
        if [[ -n "$UPDATE_CONF" ]]; then
            # 설정이 존재하는 경우
            if [[ "$UPDATE_CONF" == *"any"* ]]; then
                # any가 포함되면 취약 
                VULN_STATUS=1
                VULN_FLAGS+=("U_51_2")
                echo -e "${RED}[취약]${NC} 동적 업데이트가 전체 허용(any)으로 설정되어 있습니다."
                echo -e "   -> 발견된 설정: $UPDATE_CONF"
            else
                # none 또는 특정 IP인 경우 양호 
                echo -e "${GREEN}[양호]${NC} 동적 업데이트가 비활성화(none)되거나 제한되어 있습니다."
                echo -e "   -> 현재 설정: $UPDATE_CONF"
            fi
        else
            # 설정이 없는 경우 (U_51_3)
            # BIND 최신 버전은 기본값이 deny(none)이지만, 가이드라인은 명시적 설정을 권고함 
            # 여기서는 '취약'보다는 '설정 권고(Warning)' 수준으로 처리하거나, 가이드라인 엄격 적용 시 '취약' 처리
            # PDF의 '조치 방법'에 "allow-update { none; };" 추가라고 명시되어 있으므로, 없으면 취약으로 간주하는 것이 안전함.
            VULN_STATUS=1
            VULN_FLAGS+=("U_51_3")
            echo -e "${RED}[취약]${NC} 'allow-update' 설정이 발견되지 않았습니다. (명시적 차단 권고)"
            echo -e "   -> 조치 권고: allow-update { none; }; 설정 추가 "
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
    echo -e "결과: ${GREEN}[양호]${NC} (동적 업데이트 설정이 안전합니다)"
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
