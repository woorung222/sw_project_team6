#!/bin/bash

# [U-58] 불필요한 SNMP 서비스 구동 점검
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.141-142 [cite: 1558-1584]
# 점검 목적 : 불필요한 SNMP 서비스를 비활성화하여 시스템 중요 정보 유출 및 불법 수정 방지
# 자동 조치 가능 유무 : 가능 (서비스 중지)
# 플래그 설명:
#   U_58_1 : [Service] SNMP 서비스(snmpd) 활성화 (취약)
#   U_58_2 : [Package] SNMP 패키지 설치됨 (서비스 중지 상태라도 존재함)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-58] 불필요한 SNMP 서비스 구동 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 확인
# Linux(Rocky 9)에서는 'net-snmp' 패키지가 snmpd 데몬을 제공함
PKG_CHECK=$(rpm -qa | grep "net-snmp")

if [[ -z "$PKG_CHECK" ]]; then
    echo -e "${GREEN}[양호]${NC} SNMP 서비스 패키지(net-snmp)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 서비스 상태 점검
echo -e "${YELLOW}[정보]${NC} SNMP 패키지가 설치되어 있습니다. 서비스 상태를 확인합니다."

# Systemd 서비스 활성화 여부 확인 (PDF p.142)
IS_ACTIVE=$(systemctl is-active snmpd 2>/dev/null)

if [[ "$IS_ACTIVE" == "active" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_58_1")
    echo -e "${RED}[취약]${NC} [Service] SNMP 서비스(snmpd)가 활성화(active) 상태입니다."
else
    # 서비스는 꺼져 있지만 패키지는 설치된 상태
    VULN_FLAGS+=("U_58_2")
    echo -e "${YELLOW}[경고]${NC} [Package] SNMP 패키지가 설치되어 있으나, 서비스는 비활성화 상태입니다."
    echo -e "   -> 패키지명: $(echo $PKG_CHECK | tr '\n' ' ')"
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (SNMP 서비스 비활성화)"
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
