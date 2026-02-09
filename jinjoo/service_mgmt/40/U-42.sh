#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 가이드에 명시된 불필요한 RPC 서비스 15종 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_42_1=0  # [1. inetd] 내 RPC 서비스 설정 여부
U_42_2=0  # [2. xinetd] 내 RPC 서비스 설정 여부
U_42_3=0  # [3. systemd] 및 rpcinfo 기반 서비스 활성 여부

VULN_FLAGS=""

# 가이드 명시 불필요 RPC 서비스 리스트 (15종)
RPC_LIST="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

echo "----------------------------------------------------"
echo "[U-42] 점검 시작: 불필요한 RPC 서비스 비활성화"

# [Step 1] 1. inetd 설정 확인
echo "[Step 1] /etc/inetd.conf 내 RPC 서비스 확인"
if [ -f "/etc/inetd.conf" ]; then
    INETD_RPC=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$RPC_LIST")
    if [ -n "$INETD_RPC" ]; then
        echo "▶ 1. inetd: [ 취약 ] 불필요한 RPC 서비스가 활성화되어 있습니다."
        U_42_1=1; VULN_FLAGS="$VULN_FLAGS U_42_1"
    else
        echo "▶ 1. inetd: [ 양호 ]"
    fi
else
    echo "▶ 1. inetd: [ 양호 ] (파일 미존재)"
fi

# [Step 2] 2. xinetd 설정 확인
echo "[Step 2] /etc/xinetd.d/ 내 RPC 서비스 확인"
if [ -d "/etc/xinetd.d" ]; then
    XINETD_RPC=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$RPC_LIST")
    if [ -n "$XINETD_RPC" ]; then
        echo "▶ 2. xinetd: [ 취약 ] 불필요한 RPC 서비스가 활성화되어 있습니다."
        U_42_2=1; VULN_FLAGS="$VULN_FLAGS U_42_2"
    else
        echo "▶ 2. xinetd: [ 양호 ]"
    fi
else
    echo "▶ 2. xinetd: [ 양호 ] (디렉터리 미존재)"
fi

# [Step 3] 3. systemd 및 실시간 서비스 확인
echo "[Step 3] systemd 유닛 및 rpcinfo 서비스 확인"
# systemd 유닛 상태 확인
SYSTEMD_RPC=$(systemctl list-unit-files 2>/dev/null | grep -iE "$RPC_LIST" | grep "enabled")

# rpcinfo -p 결과 확인 (가장 확실한 실시간 점검)
if command -v rpcinfo > /dev/null; then
    RPCINFO_RPC=$(rpcinfo -p 2>/dev/null | grep -iE "$RPC_LIST")
fi

if [ -n "$SYSTEMD_RPC" ] || [ -n "$RPCINFO_RPC" ]; then
    echo "▶ 3. systemd/rpcinfo: [ 취약 ] 실행 중이거나 활성화된 RPC 서비스가 존재합니다."
    U_42_3=1; VULN_FLAGS="$VULN_FLAGS U_42_3"
else
    echo "▶ 3. systemd/rpcinfo: [ 양호 ]"
fi

echo "----------------------------------------------------"
echo "U_42_1 : $U_42_1"
echo "U_42_2 : $U_42_2"
echo "U_42_3 : $U_42_3"

# 최종 판정
if [[ $U_42_1 -eq 0 && $U_42_2 -eq 0 && $U_42_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
