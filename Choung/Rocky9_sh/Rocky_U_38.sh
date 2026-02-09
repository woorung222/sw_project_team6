#!/bin/bash

# [U-38] DoS 공격에 취약한 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# [cite_start]가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.83-85 [cite: 362-422]
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 비활성화)
# 플래그 설명:
#   U_38_1 : [inetd] inetd 설정 내 해당 서비스 활성화 발견
#   U_38_2 : [xinetd] xinetd 설정 내 해당 서비스 활성화 발견
#   U_38_3 : [systemd] echo, discard, daytime, chargen 서비스 활성화 발견
#   U_38_4 : [Port] 포트(7, 9, 13, 19, 123, 161, 53, 25) 오픈 여부

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-38] DoS 공격에 취약한 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 서비스 정규식 (기본 DoS 서비스)
DOS_SVCS="echo|discard|daytime|chargen"

# 1. [systemd] 점검 (U_38_3) - PDF p.84
SYSTEMD_CHECK=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "$DOS_SVCS" | grep -w "active")

if [[ -n "$SYSTEMD_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_38_3")
    echo -e "${RED}[취약]${NC} [systemd] DoS 취약 서비스(echo/discard/daytime/chargen)가 활성화되어 있습니다."
fi

# 2. [xinetd] 점검 (U_38_2) - PDF p.84
if [[ -d "/etc/xinetd.d" ]]; then
    XINETD_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$DOS_SVCS" | grep -iw "no")
    if [[ -n "$XINETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_38_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 DoS 취약 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_38_1) - PDF p.83
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -E "$DOS_SVCS")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_38_1")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 DoS 취약 서비스가 활성화되어 있습니다."
    fi
fi

# 4. [Port] 포트 점검 (U_38_4) - 요청사항 반영
# 점검 대상 포트: 7(echo), 9(discard), 13(daytime), 19(chargen), 25(SMTP), 53(DNS), 123(NTP), 161(SNMP)
# ss 명령어를 사용하여 Listen 중인 포트 확인
# grep 정규식: :(포트번호) 로 끝나거나($) 뒤에 공백이 있는 경우 매칭
echo "----------------------------------------------------------------"
echo "[INFO] DoS 취약 서비스 관련 포트 활성화 여부 확인 중..."

OPEN_PORTS=$(ss -tuln | awk '{print $5}' | grep -E ":(7|9|13|19|25|53|123|161)$")

if [[ -n "$OPEN_PORTS" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_38_4")
    echo -e "${RED}[취약]${NC} [Port] DoS 공격에 취약할 수 있는 포트가 열려 있습니다."
    echo -e "   -> 발견된 포트:\n$OPEN_PORTS"
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} DoS 공격에 취약한 서비스 및 포트가 비활성화되어 있습니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    # 정렬 및 중복 제거
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
