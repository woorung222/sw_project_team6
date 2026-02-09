#!/bin/bash

# [U-63] sudo 명령어 접근 관리
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.159 [cite: 1957-1974]
# 점검 목적 : 관리자 권한을 부여하는 설정 파일(sudoers)의 비인가 수정을 방지하기 위함
# 자동 조치 가능 유무 : 가능 (파일 소유자 및 권한 변경)
# 플래그 설명:
#   U_63_1 : [File] /etc/sudoers 파일 소유자가 root가 아님
#   U_63_2 : [File] /etc/sudoers 파일 권한이 640 초과 (예: 644, 666 등)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-63] sudo 명령어 접근 관리 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 확인
# sudo 패키지는 필수 요소지만, 규칙에 따라 확인
PKG_CHECK=$(rpm -qa | grep "^sudo-[0-9]")

if [[ -z "$PKG_CHECK" ]]; then
    echo -e "${GREEN}[양호]${NC} sudo 패키지가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 파일 점검 (/etc/sudoers)
SUDOERS_FILE="/etc/sudoers"

if [[ -f "$SUDOERS_FILE" ]]; then
    # 파일 정보 추출 (소유자, 권한-숫자)
    FILE_OWNER=$(stat -c "%U" "$SUDOERS_FILE")
    FILE_PERM=$(stat -c "%a" "$SUDOERS_FILE")
    
    echo -e "${YELLOW}[정보]${NC} $SUDOERS_FILE 파일 점검"
    echo -e "   -> 현재 소유자: $FILE_OWNER"
    echo -e "   -> 현재 권한: $FILE_PERM"

    # 3-1. 소유자 점검 (root 여부)
    if [[ "$FILE_OWNER" != "root" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_63_1")
        echo -e "${RED}[취약]${NC} [File] 소유자가 root가 아닙니다."
    fi

    # 3-2. 권한 점검 (640 이하 여부)
    # 440(기본값), 400, 600, 640 모두 양호
    if [[ "$FILE_PERM" -gt 640 ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_63_2")
        echo -e "${RED}[취약]${NC} [File] 권한이 640보다 높습니다. (비인가자 읽기 가능 위험)"
    fi
    
    if [[ $VULN_STATUS -eq 0 ]]; then
         echo -e "${GREEN}[양호]${NC} [File] 소유자(root) 및 권한($FILE_PERM <= 640) 설정이 안전합니다."
    fi

else
    # 파일이 없는 경우 (매우 드문 케이스이나 에러 처리)
    echo -e "${YELLOW}[정보]${NC} /etc/sudoers 파일을 찾을 수 없습니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (sudoers 파일 보안 설정 안전)"
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
