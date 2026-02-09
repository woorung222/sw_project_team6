#!/bin/bash

# [U-67] 로그 디렉터리 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.171 
# 점검 목적 : 로그 파일의 무단 변조 및 삭제를 방지하기 위해 소유자 및 권한을 제한함
# 자동 조치 가능 유무 : 가능 (소유자 및 권한 변경)
# 플래그 설명:
#   U_67_1 : [Owner] 로그 파일 소유자가 root가 아님
#   U_67_2 : [Perm] 로그 파일 권한이 644 초과 (그룹/타인 쓰기 권한 존재 등)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-67] 로그 디렉터리 소유자 및 권한 설정 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 점검할 주요 로그 파일 목록 (시스템 핵심 로그 위주)
# /var/log 디렉터리 전체를 뒤지면 회전된 로그(messages-2023...) 등으로 인해 노이즈가 많음
# 따라서 핵심 로그 파일들을 우선적으로 점검
LOG_FILES=(
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/maillog"
    "/var/log/cron"
    "/var/log/boot.log"
    "/var/log/dmesg"
    "/var/log/syslog"
)

echo -e "${YELLOW}[정보]${NC} 주요 로그 파일의 소유자(root) 및 권한(644 이하)을 점검합니다."

EXIST_COUNT=0

for FILE in "${LOG_FILES[@]}"; do
    if [[ -f "$FILE" ]]; then
        EXIST_COUNT=$((EXIST_COUNT+1))
        
        # 1. 소유자 확인
        OWNER=$(stat -c "%U" "$FILE")
        
        # 2. 권한 확인 (숫자 모드)
        PERM=$(stat -c "%a" "$FILE")
        
        # 상세 점검
        IS_VULN_OWNER=0
        IS_VULN_PERM=0
        
        # 소유자가 root가 아니면 취약
        if [[ "$OWNER" != "root" ]]; then
            IS_VULN_OWNER=1
            VULN_STATUS=1
            # 중복 방지
            if [[ ! "${VULN_FLAGS[*]}" =~ "U_67_1" ]]; then VULN_FLAGS+=("U_67_1"); fi
        fi
        
        # 권한이 644보다 크면 취약 (단순 숫자 비교보다 비트 연산이 정확하나, 가이드 기준 644 초과 여부 확인)
        # 644 = rw-r--r--
        # 취약 예시: 664(그룹쓰기), 666(전체쓰기), 777 등
        # 640, 600 은 양호
        if [[ "$PERM" -gt 644 ]]; then
            IS_VULN_PERM=1
            VULN_STATUS=1
            if [[ ! "${VULN_FLAGS[*]}" =~ "U_67_2" ]]; then VULN_FLAGS+=("U_67_2"); fi
        fi
        
        # 결과 출력
        if [[ $IS_VULN_OWNER -eq 1 ]] || [[ $IS_VULN_PERM -eq 1 ]]; then
            echo -e "${RED}[취약]${NC} $FILE (Owner: $OWNER, Perm: $PERM)"
            if [[ $IS_VULN_OWNER -eq 1 ]]; then echo -e "      -> 소유자가 root가 아닙니다."; fi
            if [[ $IS_VULN_PERM -eq 1 ]]; then echo -e "      -> 권한이 644를 초과합니다."; fi
        else
            echo -e "${GREEN}[양호]${NC} $FILE (Owner: $OWNER, Perm: $PERM)"
        fi
    fi
done

if [[ $EXIST_COUNT -eq 0 ]]; then
    echo -e "${YELLOW}[정보]${NC} 점검할 주요 로그 파일이 존재하지 않습니다. (rsyslog 설정 확인 필요)"
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (로그 파일 권한 및 소유자 적절)"
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
