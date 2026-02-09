#!/bin/bash

# [U-41] 불필요한 automountd 제거
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.93-95
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 비활성화)
# 플래그 설명:
#   U_41_1 : [Running] automountd(autofs) 서비스 또는 프로세스가 현재 실행 중 (취약)
#   U_41_2 : [Boot] autofs 서비스가 부팅 시 자동 실행되도록 설정됨 (취약)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-41] 불필요한 automountd 제거 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [Running] 현재 실행 여부 점검 (U_41_1)
# systemd 서비스가 active 상태이거나, 프로세스가 메모리에 떠 있는지 확인 (OR 조건)
SVC_ACTIVE=$(systemctl is-active autofs 2>/dev/null)
PROC_CHECK=$(ps -ef | grep -v grep | grep -E "automount|autofs")

if [[ "$SVC_ACTIVE" == "active" ]] || [[ -n "$PROC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_41_1")
    echo -e "${RED}[취약]${NC} [Running] automountd(autofs) 서비스가 현재 실행 중입니다."
    if [[ "$SVC_ACTIVE" == "active" ]]; then
        echo "   -> Service State: active"
    fi
    if [[ -n "$PROC_CHECK" ]]; then
        echo "   -> Process State: running"
    fi
fi

# 2. [Boot] 부팅 시 자동 실행 설정 점검 (U_41_2)
# systemctl is-enabled 명령어로 enabled 상태인지 확인
SVC_ENABLED=$(systemctl is-enabled autofs 2>/dev/null)

if [[ "$SVC_ENABLED" == "enabled" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_41_2")
    echo -e "${RED}[취약]${NC} [Boot] autofs 서비스가 부팅 시 자동 실행되도록 설정되어 있습니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} automountd(autofs) 서비스가 비활성화되어 있습니다."
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
