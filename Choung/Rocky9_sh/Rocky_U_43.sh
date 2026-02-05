#!/bin/bash

# [U-43] NIS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.99-101
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_43_1 : [systemd/Process] NIS 서비스(ypserv, ypbind 등) 활성화 발견
#   U_43_2 : [xinetd] xinetd 설정 내 NIS 서비스 활성화 발견
#   U_43_3 : [inetd] inetd 설정 내 NIS 서비스 활성화 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-43] NIS 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 NIS 서비스 목록 (가이드라인 p.99 참고)
# ypserv: NIS 서버
# ypbind: NIS 클라이언트
# ypxfrd, rpc.yppasswdd, rpc.ypupdated: 관련 데몬
NIS_TARGETS=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")

# 정규식 생성 (grep -E 용)
NIS_REGEX=$(IFS="|"; echo "${NIS_TARGETS[*]}")

# 1. [systemd/Process] 점검 (U_43_1) - PDF p.100 
# Systemd 유닛 활성화 여부 확인
# 패키지 미설치 시 결과가 없으므로 안전 처리됨
SYS_CHECK=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "$NIS_REGEX" | grep -w "active")

# 프로세스 실행 여부 확인
PROC_CHECK=""
for svc in "${NIS_TARGETS[@]}"; do
    if ps -e -o comm | grep -xw "$svc" >/dev/null; then
        PROC_CHECK="$PROC_CHECK $svc"
    fi
done

if [[ -n "$SYS_CHECK" ]] || [[ -n "$PROC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_43_1")
    echo -e "${RED}[취약]${NC} [systemd/Process] NIS 관련 서비스가 활성화되어 있습니다."
    [[ -n "$SYS_CHECK" ]] && echo "   -> Systemd 활성화 유닛 발견"
    [[ -n "$PROC_CHECK" ]] && echo "   -> Process 실행중: $PROC_CHECK"
fi

# 2. [xinetd] 점검 (U_43_2) - PDF p.100 
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 설정 확인
    XINETD_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$NIS_REGEX" | grep -iw "no")
    if [[ -n "$XINETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_43_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 NIS 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_43_3) - PDF p.99 
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석 제외하고 설정 존재 여부 확인
    INETD_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -E "$NIS_REGEX")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_43_3")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 NIS 서비스가 활성화되어 있습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} NIS 관련 모든 서비스가 비활성화되어 있습니다."
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

