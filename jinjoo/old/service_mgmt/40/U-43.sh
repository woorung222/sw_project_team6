#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NIS 서비스(ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated) 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

U_43=0  # NIS, NIS+ 서비스 활성화 여부 통합 플래그

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-43] 점검 시작: NIS, NIS+ 서비스 비활성화"

# [점검 프로세스 리스트]
# ypserv: NIS 서버
# ypbind: NIS 클라이언트
# ypxfrd: NIS 지도 전송
# rpc.yppasswdd: NIS 패스워드 변경
# rpc.ypupdated: NIS 업데이트

# 1. NIS 관련 프로세스 실행 여부 확인
# 명령어: ps -ef | grep [서비스명]
echo "[Step 1] 가이드 명시 NIS 관련 프로세스 가동 상태 확인"
NIS_PS=$(ps -ef | grep -iE "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep")

# 2. NIS 관련 서비스 유닛 활성화 여부 확인 (systemd)
echo "[Step 2] NIS 관련 서비스 유닛 활성화 여부 확인"
NIS_UNITS=$(systemctl list-unit-files 2>/dev/null | grep -iE "ypserv|ypbind|ypxfrd|yppasswdd|ypupdated|nis" | grep "enabled")

if [ -n "$NIS_PS" ] || [ -n "$NIS_UNITS" ]; then
    echo "▶ 점검 결과: [ 취약 ] NIS 관련 서비스가 가동 중이거나 활성화되어 있습니다."
    [ -n "$NIS_PS" ] && echo "  - 발견된 프로세스: $(echo "$NIS_PS" | awk '{print $8}' | xargs)"
    [ -n "$NIS_UNITS" ] && echo "  - 발견된 유닛: $(echo "$NIS_UNITS" | awk '{print $1}' | xargs)"
    U_43=1
    VULN_FLAGS="U_43"
else
    echo "▶ 점검 결과: [ 양호 ]"
fi

echo "----------------------------------------------------"
echo "U_43 : $U_43"

# 최종 판정
if [ $U_43 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
