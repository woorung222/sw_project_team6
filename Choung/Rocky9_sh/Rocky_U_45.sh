#!/bin/bash

# [U-45] 메일 서비스 버전 점검
# 대상 운영체제 : Rocky Linux 9
# 자동 조치 가능 유무 : 가능 (dnf update)
# 플래그 설명:
#   U_45_1 : Sendmail 존재 (경고)
#   U_45_2 : Postfix 존재 (경고)
#   U_45_3 : Exim 존재 (경고)
#   U_45_4 : Sendmail 버전 미흡 (취약)
#   U_45_5 : Postfix 버전 미흡 (취약)
#   U_45_6 : Exim 버전 미흡 (취약)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-45] 메일 서비스 버전 점검 시작 (Sendmail, Postfix, Exim)"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 MTA 리스트
# 가이드라인 대상: Sendmail , Postfix , Exim 
MTA_NAMES=("sendmail" "postfix" "exim")
W_FLAGS=("U_45_1" "U_45_2" "U_45_3")
V_FLAGS=("U_45_4" "U_45_5" "U_45_6")

for i in "${!MTA_NAMES[@]}"; do
    MTA="${MTA_NAMES[$i]}"
    W_FLAG="${W_FLAGS[$i]}"
    V_FLAG="${V_FLAGS[$i]}"
    
    DETECTED=0
    
    # 1. 패키지 설치 확인 (rpm)
    PKG_VER=$(rpm -q "$MTA" --queryformat '%{VERSION}-%{RELEASE}' 2>/dev/null)
    if [ $? -eq 0 ]; then
        DETECTED=1
    fi
    
    # 2. 프로세스 실행 확인 (ps) - 정확한 단어 매칭
    if ps -e -o comm | grep -v "grep" | grep -xw "$MTA" >/dev/null 2>&1; then
        DETECTED=1
    fi

    # 감지되었을 경우에만 내부 로직 진입
    if [ $DETECTED -eq 1 ]; then
        VULN_FLAGS+=("$W_FLAG")
        echo -e "${YELLOW}[경고]${NC} $MTA 서비스 또는 패키지가 감지되었습니다."

        # 3. 최신 버전 대조 (dnf check-update) [cite: 823]
        # 업데이트 가능 목록에 이름이 나오면 최신 버전이 아님
        UPGRADE_AVAILABLE=$(dnf check-update "$MTA" -q | grep -w "$MTA" | awk '{print $2}')
        
        if [ ! -z "$UPGRADE_AVAILABLE" ]; then
            echo -e "${RED}[취약]${NC} $MTA 가 최신 버전이 아닙니다. (최신 패치 권고)" [cite: 823]
            VULN_STATUS=1
            VULN_FLAGS+=("$V_FLAG")
        else
            echo -e "${GREEN}[양호]${NC} $MTA 가 최신 버전으로 확인되었습니다." [cite: 823]
            echo "  [참고] 사용하지 않는다면 서비스를 중지 및 비활성화하십시오." [cite: 823]
        fi
    else
        echo -e "${GREEN}[양호]${NC} $MTA 서비스가 설치되어 있지 않으며 실행 중도 아닙니다."
    fi
    echo ""
done

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [ $VULN_STATUS -eq 0 ]; then
    echo -e "결과: ${GREEN}[양호]${NC}"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [ ${#VULN_FLAGS[@]} -eq 0 ]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -V | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
