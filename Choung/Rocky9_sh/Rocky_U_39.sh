#!/bin/bash

# [U-39] 불필요한 NFS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.86-88
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_39_1 : [systemd] nfs-server 서비스 활성화 발견
#   U_39_2 : [Process] nfsd 등 실제 프로세스 실행 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-39] 불필요한 NFS 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [systemd] 점검 (U_39_1) - PDF p.86 
# Rocky 9에서 NFS 메인 서비스는 'nfs-server.service'입니다.
# 패키지가 없으면 'not found' 등이 뜨고 active가 아니므로 안전 처리됩니다.
NFS_SVC_CHECK=$(systemctl is-active nfs-server 2>/dev/null | grep -w "active")

if [[ -n "$NFS_SVC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_39_1")
    echo -e "${RED}[취약]${NC} [systemd] nfs-server 서비스가 활성화(active) 되어 있습니다."
fi

# 2. [Process] 점검 (U_39_2) - PDF p.87 (AIX 사례 참조하여 Linux 적용) 
# 실제 커널 스레드([nfsd])나 데몬(rpc.nfsd, nfsd)이 떠 있는지 확인
NFS_PROC_CHECK=$(ps -ef | grep -v grep | grep -E "nfsd|rpc.nfsd|rpc.mountd")

if [[ -n "$NFS_PROC_CHECK" ]]; then
    VULN_STATUS=1
    # 플래그 중복 방지 (systemd가 잡았으면 굳이 중복일 수 있으나, 프로세스만 떠 있는 경우 대비)
    [[ ! " ${VULN_FLAGS[@]} " =~ " U_39_1 " ]] && VULN_FLAGS+=("U_39_2")
    echo -e "${RED}[취약]${NC} [Process] NFS 관련 프로세스(nfsd, mountd)가 실행 중입니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} NFS 서비스가 비활성화되어 있습니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
