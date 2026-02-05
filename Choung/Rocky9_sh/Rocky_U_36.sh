#!/bin/bash

# [U-36] r-command 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.77-79
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_36_1 : [systemd] r-command 서비스(rlogin, rsh, rexec) 활성화 발견
#   U_36_2 : [xinetd] xinetd 설정 내 r-command 활성화 발견
#   U_36_3 : [inetd] inetd 설정 내 r-command 활성화 발견
#   U_36_4 : [파일] hosts.equiv 또는 .rhosts 파일 발견 (인증 우회 위험)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-36] r-command 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [systemd] 점검 (U_36_1) - PDF p.78 
# 패키지 미설치 시 아무것도 출력되지 않아 안전함
R_SVC_CHECK=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "rlogin|rsh|rexec" | grep -w "active")
if [[ -n "$R_SVC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_36_1")
    echo -e "${RED}[취약]${NC} [systemd] r-command 서비스 또는 소켓이 활성화되어 있습니다."
fi

# 2. [xinetd] 점검 (U_36_2) - PDF p.78 
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 인 경우 취약
    # rlogin, rsh, rexec 외에 shell, login, exec 명칭도 포함
    X_ANON_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "rlogin|rsh|rexec|shell|login|exec" | grep -iw "no")
    if [[ -n "$X_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_36_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 r-command 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_36_3) - PDF p.78 
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석 제외하고 설정 존재 여부 확인
    I_ANON_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -iE "rlogin|rsh|rexec|shell|login|exec")
    if [[ -n "$I_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_36_3")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 r-command 서비스가 활성화되어 있습니다."
    fi
fi

# 4. [파일] 점검 (U_36_4) - PDF p.79 
FILES_CHECK=""
[[ -f "/etc/hosts.equiv" ]] && FILES_CHECK="${FILES_CHECK} /etc/hosts.equiv"
[[ -f "/root/.rhosts" ]] && FILES_CHECK="${FILES_CHECK} /root/.rhosts"

if [[ -n "$FILES_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_36_4")
    echo -e "${RED}[취약]${NC} [파일] 인증 우회 가능 파일이 존재합니다:${FILES_CHECK}"
    
    # 정밀 점검 (권한 및 설정)
    for f in $FILES_CHECK; do
        # 권한 600 초과 확인
        PERM=$(stat -c "%a" "$f" 2>/dev/null)
        if [[ "$PERM" -gt 600 ]]; then
            echo "  -> [위험] $f 파일 권한($PERM)이 600을 초과합니다."
        fi
        # '+ +' 설정 확인
        if grep -q "+ +" "$f" 2>/dev/null; then
            echo "  -> [위험] $f 내에 '+ +' (모든 접근 허용) 설정이 있습니다."
        fi
    done
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} r-command 서비스 미설치 및 관련 설정 파일이 안전합니다."
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
