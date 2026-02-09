#!/bin/bash

# [U-34] Finger 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.68
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_34_1 : [systemd/Process] Finger 서비스 또는 프로세스 활성화 발견
#   U_34_2 : [xinetd] /etc/xinetd.d/finger 내 활성화 설정 발견
#   U_34_3 : [inetd] /etc/inetd.conf 내 finger 설정 활성화 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-34] Finger 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [systemd/Process] 점검 (U_34_1)
# [[ ]] 구문을 사용하여 변수가 비어있어도 오류가 나지 않도록 처리
FINGER_SYSTEMD=$(systemctl is-active finger.socket finger.service 2>/dev/null | grep -w "active")
FINGER_PROC=$(ps -e -o comm | grep -v "grep" | grep -xw "fingerd")

if [[ -z "$FINGER_SYSTEMD" && -z "$FINGER_PROC" ]]; then
    # 양호 상황 (아무것도 감지되지 않음)
    :
else
    # 취약 상황 (하나라도 감지됨)
    VULN_STATUS=1
    VULN_FLAGS+=("U_34_1")
    echo -e "${RED}[취약]${NC} [systemd/Process] Finger 서비스 또는 프로세스가 감지되었습니다."
fi

# 2. [xinetd] 설정 점검 (U_34_2)
if [[ -f "/etc/xinetd.d/finger" ]]; then
    # disable 옵션이 'no'인 경우 취약
    if grep -i "disable" /etc/xinetd.d/finger | grep -iw "no" >/dev/null; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_34_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 Finger 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 설정 점검 (U_34_3)
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석(#)을 제외하고 finger 서비스가 포함된 행이 있는지 확인
    if grep -v "^#" /etc/inetd.conf | grep -iw "finger" >/dev/null; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_34_3")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 Finger 서비스가 활성화되어 있습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} Finger 서비스가 비활성화되어 있습니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    # 정렬 및 중복 제거 후 출력
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
