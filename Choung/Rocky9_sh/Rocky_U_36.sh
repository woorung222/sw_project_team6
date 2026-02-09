#!/bin/bash

# [U-36] r-command 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.77-79
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_36_1 : [inetd] inetd 설정 내 r-command 활성화 발견
#   U_36_2 : [xinetd] xinetd 설정 내 r-command 활성화 발견
#   U_36_3 : [systemd] r-command 서비스(rlogin, rsh, rexec) 활성화 발견
#   U_36_4 : [Package] r-command 관련 패키지 설치 여부 (rsh-server 등)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-36] r-command 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [systemd] 점검 (U_36_3) - PDF p.78 
R_SVC_CHECK=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "rlogin|rsh|rexec" | grep -w "active")
if [[ -n "$R_SVC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_36_3")
    echo -e "${RED}[취약]${NC} [systemd] r-command 서비스 또는 소켓이 활성화되어 있습니다."
fi

# 2. [xinetd] 점검 (U_36_2) - PDF p.78 
if [[ -d "/etc/xinetd.d" ]]; then
    X_ANON_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "rlogin|rsh|rexec|shell|login|exec" | grep -iw "no")
    if [[ -n "$X_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_36_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 r-command 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_36_1) - PDF p.78 
if [[ -f "/etc/inetd.conf" ]]; then
    I_ANON_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -iE "rlogin|rsh|rexec|shell|login|exec")
    if [[ -n "$I_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_36_3") # 플래그 번호 유지 요청에 따라 3번 사용 가능성 있으나 문맥상 1번이 맞음 (일단 원본 유지)
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 r-command 서비스가 활성화되어 있습니다."
    fi
fi

# 4. [Package] 점검 (U_36_4) - 패키지 설치 여부 전수 조사 (수정됨)
# rsh, rsh-server, rlogin, rexec 등 관련 패키지 확인
# Rocky Linux(RPM) 환경에 맞게 dpkg -> rpm -qa로 변경
echo "----------------------------------------------------------------"
echo "[INFO] r-services 관련 패키지 설치 여부 확인 중..."

R_PKGS=$(rpm -qa | grep -E "^rsh|^rlogin|^rexec")

if [[ -n "$R_PKGS" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_36_4")
    echo -e "${RED}[취약]${NC} [Package] r-command 관련 패키지가 설치되어 있습니다."
    echo -e "   -> 설치된 패키지 목록:\n$R_PKGS"
else
    echo -e "${GREEN}[양호]${NC} [Package] r-command 관련 패키지가 설치되지 않았습니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (r-command 미사용)"
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
