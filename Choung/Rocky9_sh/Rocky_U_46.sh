#!/bin/bash

# [U-46] 일반 사용자의 메일 서비스 실행 방지
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.111-112
# 자동 조치 가능 유무 : 가능 (설정 변경 및 권한 수정)
# 플래그 설명:
#   U_46_1 : [Sendmail] restrictqrun 옵션 누락
#   U_46_2 : [Postfix] /usr/sbin/postsuper 일반 사용자 실행 권한(o+x) 존재
#   U_46_3 : [Exim] /usr/sbin/exiqgrep 일반 사용자 실행 권한(o+x) 존재

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-46] 일반 사용자의 메일 서비스 실행 방지 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [Sendmail] 점검 (U_46_1) - PDF p.111
if systemctl is-active sendmail >/dev/null 2>&1; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [[ -f "$CF_FILE" ]]; then
        # PrivacyOptions 행에서 restrictqrun 옵션 확인
        # 주석(#) 제외하고 검색
        CHECK_OPT=$(grep -v "^#" "$CF_FILE" | grep -i "PrivacyOptions" | grep -i "restrictqrun")
        
        if [[ -z "$CHECK_OPT" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_46_1")
            echo -e "${RED}[취약]${NC} [Sendmail] PrivacyOptions에 'restrictqrun' 옵션이 없습니다."
        else
            echo -e "${GREEN}[양호]${NC} [Sendmail] restrictqrun 옵션이 설정되어 있습니다."
        fi
    else
        echo -e "${RED}[취약]${NC} [Sendmail] 설정 파일($CF_FILE)이 없습니다."
        VULN_STATUS=1
        VULN_FLAGS+=("U_46_1")
    fi
else
    echo -e "${GREEN}[양호]${NC} [Sendmail] 서비스 비활성화 상태입니다."
fi

# 2. [Postfix] 점검 (U_46_2) - PDF p.111
# Postfix 관리 명령(postsuper)은 root만 실행해야 함
if systemctl is-active postfix >/dev/null 2>&1; then
    TARGET_BIN="/usr/sbin/postsuper"
    if [[ -f "$TARGET_BIN" ]]; then
        # Other 권한에 실행(x) 비트가 있는지 확인
        PERM=$(stat -c "%a" "$TARGET_BIN") # 예: 755
        OTHER_PERM=${PERM: -1}             # 마지막 자리 (Other)
        
        # Other 권한이 1, 3, 5, 7 중 하나면 실행 권한이 있는 것 (홀수)
        if [[ $((OTHER_PERM % 2)) -eq 1 ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_46_2")
            echo -e "${RED}[취약]${NC} [Postfix] $TARGET_BIN 파일에 일반 사용자 실행 권한($PERM)이 있습니다."
            echo "   -> 조치: chmod o-x $TARGET_BIN"
        else
            echo -e "${GREEN}[양호]${NC} [Postfix] $TARGET_BIN 실행 권한이 제한되어 있습니다($PERM)."
        fi
    else
        # Postfix가 켜져있는데 파일이 없으면 이상하지만, 파일이 없으므로 실행 위험도 없음
        echo -e "${GREEN}[양호]${NC} [Postfix] $TARGET_BIN 파일이 존재하지 않습니다."
    fi
else
    echo -e "${GREEN}[양호]${NC} [Postfix] 서비스 비활성화 상태입니다."
fi

# 3. [Exim] 점검 (U_46_3) - PDF p.112
if systemctl is-active exim >/dev/null 2>&1; then
    TARGET_BIN="/usr/sbin/exiqgrep"
    if [[ -f "$TARGET_BIN" ]]; then
        PERM=$(stat -c "%a" "$TARGET_BIN")
        OTHER_PERM=${PERM: -1}
        
        if [[ $((OTHER_PERM % 2)) -eq 1 ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_46_3")
            echo -e "${RED}[취약]${NC} [Exim] $TARGET_BIN 파일에 일반 사용자 실행 권한($PERM)이 있습니다."
            echo "   -> 조치: chmod o-x $TARGET_BIN"
        else
            echo -e "${GREEN}[양호]${NC} [Exim] $TARGET_BIN 실행 권한이 제한되어 있습니다($PERM)."
        fi
    fi
else
    echo -e "${GREEN}[양호]${NC} [Exim] 서비스 비활성화 상태입니다."
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (메일 서비스 일반 사용자 실행 제한 설정됨)"
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
