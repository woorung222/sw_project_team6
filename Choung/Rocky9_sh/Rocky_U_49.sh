#!/bin/bash

# [U-49] DNS 보안 버전 패치
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.118-120
# 자동 조치 가능 유무 : 수동 조치 (dnf update bind)
# 플래그 설명:
#   U_49_1 : [Service] DNS 서비스(named) 활성화 상태
#   U_49_2 : [Version] 보안 업데이트가 필요한 구버전 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-49] DNS 보안 버전 패치 점검 시작"
echo "----------------------------------------------------------------"

# Root 권한 체크 (dnf 사용을 위해 필요)
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} 패키지 버전 확인을 위해 Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. [Service] DNS 서비스 활성화 확인 (U_49_1)
# BIND의 데몬 이름은 보통 'named' 입니다.
if systemctl is-active named >/dev/null 2>&1; then
    VULN_FLAGS+=("U_49_1")
    
    # 현재 설치된 버전 확인
    CURRENT_VER=$(named -v 2>/dev/null)
    echo -e "   -> DNS 서비스(named)가 활성화되어 있습니다. (${CURRENT_VER})"

    # 2. [Version] 업데이트 필요 여부 확인 (U_49_2)
    echo -n "   -> 최신 보안 패치 확인 중 (Repository 연동)... "
    
    # dnf check-update 반환값: 100(업데이트 있음), 0(최신), 1(오류)
    dnf check-update bind >/dev/null 2>&1
    CHECK_RES=$?

    if [[ $CHECK_RES -eq 100 ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_49_2")
        echo -e "${RED}[업데이트 필요]${NC}"
        echo -e "${RED}[취약]${NC} BIND(DNS) 서비스의 보안 패치가 시급합니다."
    elif [[ $CHECK_RES -eq 0 ]]; then
        echo -e "${GREEN}[최신 버전]${NC}"
        echo -e "${GREEN}[양호]${NC} BIND 서비스가 최신 버전으로 구동 중입니다."
    else
        echo -e "${RED}[확인 실패]${NC}"
        echo -e "${YELLOW}[주의]${NC} 네트워크 상태 또는 저장소 설정을 확인하십시오."
        # 확인 실패 시 보수적으로 취약 처리하지 않음 (단순 통신 오류일 수 있음)
    fi

else
    echo -e "${GREEN}[양호]${NC} DNS 서비스(named)를 사용하지 않고 있습니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    # 서비스가 켜져 있어도 최신 버전이면 양호로 판단
    echo -e "결과: ${GREEN}[양호]${NC}"
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
