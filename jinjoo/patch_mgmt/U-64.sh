#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 시스템의 최신 보안 패치 적용 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_64=0  # 보안 패치 및 커널 업데이트 상태

echo "----------------------------------------------------"
echo "[U-64] 점검 시작: 주기적 보안 패치 및 벤더 권고사항 적용"

# [Step 1] OS 및 커널 버전 확인
# 현재 설치된 OS 및 커널 버전 정보를 수집함
OS_VERSION=$(hostnamectl | grep "Operating System" | cut -d: -f2 | xargs)
KERNEL_VERSION=$(uname -r)

echo "[점검 사례 Step 1] OS 정보: $OS_VERSION"
echo "[점검 사례 Step 1] 커널 정보: $KERNEL_VERSION"

# [Step 2 & 3 점검] 최신 보안 패치 적용 상태 점검
# audit 사용자가 패키지 관리자를 통해 보안 저장소의 업데이트 항목 존재 여부를 확인함
echo "[INFO] 보안 패치 상태를 점검 중입니다..."

# audit 사용자가 sudo를 통해 비밀번호 없이 실행하도록 구성
sudo apt-get update -qq > /dev/null

# 보안 관련 업데이트 대기 항목 리스트 추출
SECURITY_PATCH_LIST=$(apt-get --just-print upgrade 2>/dev/null | grep -i "Inst" | grep -i "security")

if [ -z "$SECURITY_PATCH_LIST" ]; then
    # 패치 관리 정책에 따라 최신 패치를 유지하고 있는 경우 '양호'
    echo "▶ 결과: [ 양호 ] 모든 보안 패치가 최신 상태로 적용되어 있습니다."
    U_64=0
else
    # 패치 관리 정책 미수립 또는 미적용 패치가 존재하는 경우 '취약'
    echo "▶ 결과: [ 취약 ] 적용이 필요한 보안 패치가 발견되었습니다."
    U_64=1
fi

echo "----------------------------------------------------"
echo "U_64 : $U_64"

# 최종 판정
if [[ $U_64 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
fi

exit $FINAL_RESULT
