#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NFS 서비스 활성화 여부 확인 및 불필요한 서비스 비활성화 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_39_1=0  # [가이드 필수] systemctl list-units 명령어를 통한 nfs 서비스 활성 여부
U_39_2=0  # [프로세스/포트] nfsd 프로세스 및 2049/111 포트 오픈 여부
U_39_3=0  # [패키지/설정] nfs 패키지 설치 및 /etc/exports 설정 존재 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-39] 점검 시작: 불필요한 NFS 서비스 비활성화"

# [Step 1] 가이드 명시 필수 점검 (NFS 서비스 활성화 여부 확인)
# 명령어: systemctl list-units --type=service | grep nfs
echo "[Step 1] 가이드 기준 서비스 활성화 점검"
NFS_SERVICE_UNIT=$(systemctl list-units --type=service | grep nfs)

if [ -n "$NFS_SERVICE_UNIT" ]; then
    echo "▶ 서비스 점검: [ 취약 ] 활성화된 NFS 서비스 유닛이 발견되었습니다."
    echo "  - 결과: $NFS_SERVICE_UNIT"
    U_39_1=1
    VULN_FLAGS="$VULN_FLAGS U_39_1"
else
    echo "▶ 서비스 점검: [ 양호 ] (NFS 서비스 유닛이 활성 상태가 아닙니다.)"
fi


# [Step 2] 실행 중인 프로세스 및 포트 점검
echo ""
echo "[Step 2] 프로세스 및 네트워크 포트 확인"
NFS_PORT=$(sudo netstat -antup 2>/dev/null | grep -E ":(2049|111) " | grep "LISTEN")
NFS_PROC=$(ps -ef | grep -E "nfsd|mountd" | grep -v "grep")

if [ -n "$NFS_PORT" ] || [ -n "$NFS_PROC" ]; then
    echo "▶ 실행 상태: [ 취약 ] NFS 관련 프로세스 또는 포트가 가동 중입니다."
    U_39_2=1
    VULN_FLAGS="$VULN_FLAGS U_39_2"
else
    echo "▶ 실행 상태: [ 양호 ]"
fi


# [Step 3] 관련 패키지 및 설정 파일 점검
echo ""
echo "[Step 3] 패키지 및 공유 설정 파일 확인"
NFS_PKG=$(dpkg -l | grep -E "nfs-kernel-server|rpcbind" | grep "^ii")
EXPORT_CONF=$(sudo grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")

if [ -n "$NFS_PKG" ] || [ -n "$EXPORT_CONF" ]; then
    echo "▶ 패키지/설정: [ 취약 ] NFS 패키지가 존재하거나 공유 설정이 활성화되어 있습니다."
    U_39_3=1
    VULN_FLAGS="$VULN_FLAGS U_39_3"
else
    echo "▶ 패키지/설정: [ 양호 ]"
fi

echo "----------------------------------------------------"
echo "U_39_1 : $U_39_1"
echo "U_39_2 : $U_39_2"
echo "U_39_3 : $U_39_3"

# 최종 판정
if [[ $U_39_1 -eq 0 && $U_39_2 -eq 0 && $U_39_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
