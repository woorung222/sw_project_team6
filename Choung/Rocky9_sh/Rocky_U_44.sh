#!/bin/bash

# [U-44] tftp, talk 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.102-104
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_44_1 : [systemd/Process] tftp, talk, ntalk 서비스 활성화 발견
#   U_44_2 : [xinetd] xinetd 설정 내 해당 서비스 활성화 발견
#   U_44_3 : [inetd] inetd 설정 내 해당 서비스 활성화 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-44] tftp, talk 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 서비스 목록 (가이드라인 p.102) 
# tftp: 파일 전송 (인증 없음)
# talk, ntalk: 1:1 채팅 서비스
TARGET_SVCS="tftp|talk|ntalk"

# 1. [systemd/Process] 점검 (U_44_1) - PDF p.103 
# 패키지가 미설치된 경우 출력값이 없어 안전함
# active 상태인 유닛이 있는지 확인
SYS_CHECK=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "$TARGET_SVCS" | grep -w "active")

# 실제 프로세스 확인 (xinetd 하위가 아닌 독립 데몬으로 돌 경우 대비)
PROC_CHECK=""
# 프로세스 명은 tftpd, talkd 등으로 뜰 수 있음
PROC_LIST=("tftpd" "talkd" "in.tftpd" "in.talkd" "in.ntalkd")
for proc in "${PROC_LIST[@]}"; do
    if ps -e -o comm | grep -xw "$proc" >/dev/null; then
        PROC_CHECK="$PROC_CHECK $proc"
    fi
done

if [[ -n "$SYS_CHECK" ]] || [[ -n "$PROC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_44_1")
    echo -e "${RED}[취약]${NC} [systemd/Process] tftp, talk 관련 서비스가 활성화되어 있습니다."
    [[ -n "$SYS_CHECK" ]] && echo "   -> Systemd 활성화 유닛 발견"
    [[ -n "$PROC_CHECK" ]] && echo "   -> Process 실행중: $PROC_CHECK"
fi

# 2. [xinetd] 점검 (U_44_2) - PDF p.103 
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 설정 확인
    # 파일 내용에서 service tftp { ... disable = no ... } 형태를 잡아야 함
    # 간단히 grep으로 disable = no 가 있는 파일 중 타겟 서비스명이 포함된 것을 찾음
    XINETD_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$TARGET_SVCS" | grep -iw "no")
    
    if [[ -n "$XINETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_44_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 tftp/talk 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_44_3) - PDF p.102 
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석(#) 제외하고 설정 존재 여부 확인
    INETD_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -E "$TARGET_SVCS")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_44_3")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 tftp/talk 서비스가 활성화되어 있습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} tftp, talk, ntalk 서비스가 비활성화되어 있습니다."
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
