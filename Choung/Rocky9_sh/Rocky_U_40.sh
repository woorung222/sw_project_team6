#!/bin/bash

# [U-40] NFS 접근 통제
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.89-92
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_40_1 : [파일 권한] /etc/exports 권한 644 초과 또는 소유자 오류
#   U_40_2 : [접근 설정] 전체 호스트(*) 접근 허용 설정 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-40] NFS 접근 통제 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 파일
EXPORTS_FILE="/etc/exports"

# 파일 존재 여부 확인
if [[ -f "$EXPORTS_FILE" ]]; then

    # 1. [파일 권한] 점검 (U_40_1) - PDF p.90
    # 기준: 소유자 root, 권한 644 이하 [cite: 507-508]
    OWNER=$(stat -c "%U" "$EXPORTS_FILE")
    PERM=$(stat -c "%a" "$EXPORTS_FILE")

    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 644 ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_40_1")
        echo -e "${RED}[취약]${NC} [파일 권한] $EXPORTS_FILE (소유자:$OWNER, 권한:$PERM) - 644 이하/root 권고"
    fi

    # 2. [접근 설정] 점검 (U_40_2) - PDF p.90
    # 기준: 접속 허용 대상을 특정 IP나 호스트로 제한해야 함 (* 사용 금지) [cite: 509-513]
    # 주석(#) 제외하고 내용 중 '*' 문자가 포함되어 있는지 확인 (단순 경로명 제외하고 클라이언트 필드 확인 필요하나, * 자체가 위험 신호)
    # awk 등으로 정밀하게 볼 수도 있으나, grep으로 '*' 존재 여부를 1차 필터링
    
    CONTENT_CHECK=$(grep -v "^#" "$EXPORTS_FILE" | grep -F "*")
    
    if [[ -n "$CONTENT_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_40_2")
        echo -e "${RED}[취약]${NC} [접근 설정] $EXPORTS_FILE 에 전체 호스트(*) 접근 허용 설정이 존재합니다."
        echo -e "   -> 발견된 설정: $CONTENT_CHECK"
    fi

else
    # 파일이 없으면 NFS 설정을 할 수 없으므로 양호 (혹은 N/A이나 양호로 처리)
    echo "   -> /etc/exports 파일이 존재하지 않습니다. (NFS 미사용으로 간주)"
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} NFS 접근 통제 설정 파일(권한 및 내용)이 안전합니다."
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
