#!/bin/bash

# [U-52] Telnet 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.124-126 [cite: 1175-1236]
# 점검 목적 : 데이터 탈취(스니핑) 위험이 있는 Telnet 프로토콜 사용 차단
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 패키지 삭제)
# 플래그 설명:
#   U_52_1 : [inetd] /etc/inetd.conf 내 Telnet 활성화 설정 발견
#   U_52_2 : [xinetd] /etc/xinetd.d/telnet 내 disable=yes 미설정
#   U_52_3 : [systemd] telnet.socket 또는 service 활성화 상태
#   U_52_4 : [Process] 실제 Telnet 프로세스 실행 중

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-52] Telnet 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 우선 확인
# Rocky Linux에서 Telnet 서비스 데몬 패키지는 'telnet-server'임
PKG_CHECK=$(rpm -qa | grep "telnet-server")

if [[ -z "$PKG_CHECK" ]]; then
    # 패키지가 없으면 서비스가 구동될 수 없으므로 즉시 양호 처리
    echo -e "${GREEN}[양호]${NC} Telnet 서버 패키지(telnet-server)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 정밀 점검 시작
echo -e "${YELLOW}[정보]${NC} Telnet 서버 패키지가 설치되어 있습니다. 활성화 여부를 점검합니다."

# 3-1. [inetd] 설정 점검 (U_52_1)
INETD_CONF="/etc/inetd.conf"
if [[ -f "$INETD_CONF" ]]; then
    INETD_CHECK=$(grep -v "^#" "$INETD_CONF" | grep "telnet")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_52_1")
        echo -e "${RED}[취약]${NC} [inetd] 설정 파일에 Telnet 서비스가 활성화되어 있습니다."
    fi
fi

# 3-2. [xinetd] 설정 점검 (U_52_2)
XINETD_FILE="/etc/xinetd.d/telnet"
if [[ -f "$XINETD_FILE" ]]; then
    DISABLE_CHECK=$(grep "disable" "$XINETD_FILE" | grep "yes")
    if [[ -z "$DISABLE_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_52_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정 파일에 'disable = yes' 설정이 없습니다."
    fi
fi

# 3-3. [systemd] 서비스 상태 점검 (U_52_3)
SOCK_ACTIVE=$(systemctl is-active telnet.socket 2>/dev/null)
SERV_ACTIVE=$(systemctl is-active telnet.service 2>/dev/null)

if [[ "$SOCK_ACTIVE" == "active" ]] || [[ "$SERV_ACTIVE" == "active" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_52_3")
    echo -e "${RED}[취약]${NC} [systemd] Telnet 서비스/소켓이 활성화(active) 상태입니다."
    echo -e "   -> telnet.socket: $SOCK_ACTIVE"
    echo -e "   -> telnet.service: $SERV_ACTIVE"
fi

# 3-4. [Process] 실제 프로세스 점검 (U_52_4)
PROC_CHECK=$(ps -ef | grep -v grep | grep "telnet")
if [[ -n "$PROC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_52_4")
    echo -e "${RED}[취약]${NC} [Process] Telnet 관련 프로세스가 실행 중입니다."
    echo -e "   -> 프로세스: \n$PROC_CHECK"
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    # 패키지는 있지만 모든 설정과 서비스가 꺼져 있는 경우
    echo -e "결과: ${GREEN}[양호]${NC} (패키지는 설치됨, 서비스 비활성화 상태)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 5. 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
