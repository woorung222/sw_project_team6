#!/bin/bash

# [U-41] 불필요한 automountd 제거
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.93-95
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_41_1 : [systemd] autofs 서비스 활성화 발견
#   U_41_2 : [Process] automount 프로세스 실행 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-41] 불필요한 automountd 제거 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [systemd] 점검 (U_41_1) - PDF p.94
# autofs 서비스 유닛 활성화 여부 확인
# Rocky 9에서는 보통 autofs.service를 사용함
AUTO_SVC_CHECK=$(systemctl list-units --type service 2>/dev/null | grep -E "autofs|automount" | grep -w "active")

if [[ -n "$AUTO_SVC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_41_1")
    echo -e "${RED}[취약]${NC} [systemd] automountd(autofs) 서비스가 활성화되어 있습니다."
fi

# 2. [Process] 점검 (U_41_2) - PDF p.94
# 실제 프로세스가 메모리에 떠 있는지 확인
AUTO_PROC_CHECK=$(ps -ef | grep -v grep | grep -E "automount|autofs")

if [[ -n "$AUTO_PROC_CHECK" ]]; then
    VULN_STATUS=1
    # 플래그 중복 방지 (systemd와 process가 동시에 잡힐 수 있음)
    [[ ! " ${VULN_FLAGS[@]} " =~ " U_41_1 " ]] && VULN_FLAGS+=("U_41_2")
    echo -e "${RED}[취약]${NC} [Process] automount 관련 프로세스가 실행 중입니다."
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
