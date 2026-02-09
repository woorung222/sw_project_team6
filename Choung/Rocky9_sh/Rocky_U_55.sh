#!/bin/bash

# [U-55] FTP 계정 shell 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.134 [cite: 1414-1434]
# 점검 목적 : FTP 기본 계정(ftp)의 대화형 로그인 차단
# 자동 조치 가능 유무 : 가능 (usermod 명령어 사용)
# 플래그 설명:
#   U_55_1 : [Account] ftp 계정에 로그인 가능한 쉘(/bin/bash 등)이 부여됨

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-55] FTP 계정 shell 제한 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. ftp 계정 존재 여부 확인
# /etc/passwd에서 'ftp' 계정 검색
FTP_USER_CHECK=$(grep "^ftp:" /etc/passwd)

if [[ -z "$FTP_USER_CHECK" ]]; then
    # 계정이 없으면 취약점도 없음
    echo -e "${GREEN}[양호]${NC} 'ftp' 계정이 시스템에 존재하지 않습니다."
else
    # 3. 쉘 설정 확인
    # /etc/passwd의 7번째 필드(Shell) 추출
    USER_SHELL=$(echo "$FTP_USER_CHECK" | awk -F: '{print $7}')
    
    echo -e "${WARN}[정보]${NC} 'ftp' 계정이 발견되었습니다."
    echo -e "   -> 현재 쉘: $USER_SHELL"

    # 4. 로그인 불가 쉘 목록 비교 (가이드라인: /bin/false, /sbin/nologin)
    if [[ "$USER_SHELL" == "/bin/false" ]] || [[ "$USER_SHELL" == "/sbin/nologin" ]] || [[ "$USER_SHELL" == "/usr/sbin/nologin" ]]; then
        echo -e "${GREEN}[양호]${NC} ftp 계정에 로그인 제한 쉘이 설정되어 있습니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_55_1")
        echo -e "${RED}[취약]${NC} ftp 계정에 로그인 가능한 쉘이 부여되어 있습니다."
        echo -e "   -> 조치 권고: usermod -s /sbin/nologin ftp"
    fi
fi

# 5. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (FTP 계정 접근 제한)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 6. 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
