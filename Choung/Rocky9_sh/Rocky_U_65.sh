#!/bin/bash

# [U-65] NTP 및 시각 동기화 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.164-165 [cite: 2076-2118]
# 점검 목적 : 시스템 시간을 동기화하여 로그의 정확성과 신뢰성을 확보
# 자동 조치 가능 유무 : 불가능 (동기화할 타임 서버 IP 또는 도메인 지정 필요)
# 플래그 설명:
#   U_65_1 : [System] chrony 또는 ntp 패키지 미설치 (동기화 수단 없음)
#   U_65_2 : [Chrony] 서비스(chronyd) 비활성 또는 동기화 서버 미설정
#   U_65_3 : [NTP] 서비스(ntpd) 비활성 또는 동기화 서버 미설정

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-65] NTP 및 시각 동기화 설정 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. 패키지 설치 여부 확인 (chrony 우선, ntp 차선)
PKG_CHRONY=$(rpm -qa | grep "^chrony-[0-9]")
PKG_NTP=$(rpm -qa | grep "^ntp-[0-9]")

if [[ -z "$PKG_CHRONY" ]] && [[ -z "$PKG_NTP" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_65_1")
    echo -e "${RED}[취약]${NC} [System] 시간 동기화 패키지(chrony 또는 ntp)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${RED}[취약]${NC}"
    echo "Debug: Activated flag : {U_65_1}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 2. [Chrony] 점검 (Rocky Linux 9 기본)
if [[ -n "$PKG_CHRONY" ]]; then
    echo -e "${YELLOW}[정보]${NC} Chrony 패키지가 설치되어 있습니다. 상태를 점검합니다."
    
    # 2-1. 서비스 활성화 여부
    CHRONY_ACTIVE=$(systemctl is-active chronyd 2>/dev/null)
    
    # 2-2. 설정 파일 내 서버 설정 여부 (/etc/chrony.conf)
    # server 또는 pool 지시어가 주석 없이 존재하는지 확인
    CHRONY_CONF="/etc/chrony.conf"
    if [[ -f "$CHRONY_CONF" ]]; then
        SERVER_CFG=$(grep -E "^server|^pool" "$CHRONY_CONF")
    else
        SERVER_CFG=""
    fi

    if [[ "$CHRONY_ACTIVE" == "active" ]] && [[ -n "$SERVER_CFG" ]]; then
        echo -e "${GREEN}[양호]${NC} [Chrony] 서비스가 활성화되어 있고 동기화 서버가 설정되어 있습니다."
        # (참고) 실제 동기화 상태 출력
        if command -v chronyc &> /dev/null; then
            echo -e "   -> 동기화 소스 상태 (chronyc sources):"
            chronyc sources | head -3 | sed 's/^/      /'
        fi
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_65_2")
        echo -e "${RED}[취약]${NC} [Chrony] 서비스가 실행 중이지 않거나 서버 설정이 없습니다."
        echo -e "   -> Active 상태: ${CHRONY_ACTIVE:-inactive}"
        echo -e "   -> Config 설정: ${SERVER_CFG:-없음}"
    fi
fi

# 3. [NTP] 점검 (Legacy)
if [[ -n "$PKG_NTP" ]]; then
    echo -e "${YELLOW}[정보]${NC} NTP 패키지가 설치되어 있습니다. 상태를 점검합니다."
    
    # 3-1. 서비스 활성화 여부
    NTP_ACTIVE=$(systemctl is-active ntpd 2>/dev/null)
    
    # 3-2. 설정 파일 점검
    NTP_CONF="/etc/ntp.conf"
    if [[ -f "$NTP_CONF" ]]; then
        NTP_SERVER_CFG=$(grep "^server" "$NTP_CONF")
    else
        NTP_SERVER_CFG=""
    fi

    if [[ "$NTP_ACTIVE" == "active" ]] && [[ -n "$NTP_SERVER_CFG" ]]; then
        echo -e "${GREEN}[양호]${NC} [NTP] 서비스가 활성화되어 있고 동기화 서버가 설정되어 있습니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_65_3")
        echo -e "${RED}[취약]${NC} [NTP] 서비스가 실행 중이지 않거나 서버 설정이 없습니다."
    fi
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
# 패키지는 있는데 설정이 미흡한 경우 취약 처리
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (시간 동기화 설정 적용됨)"
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
