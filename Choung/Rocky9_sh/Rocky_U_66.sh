#!/bin/bash

# [U-66] 정책에 따른 시스템 로깅 설정
# 대상 운영체제 : Rocky Linux 9
# [cite_start]가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.166-167 [cite: 2120-2139]
# 점검 목적 : 주요 시스템 로그를 별도 파일로 기록하여 침해 사고 시 원인 파악 및 증거 확보
# 자동 조치 가능 유무 : 불가능 (조직의 로그 정책에 따라 설정 파일 편집 필요)
# 플래그 설명:
#   U_66_1 : [System] rsyslog 미설치 또는 서비스 비활성화
#   U_66_2 : [Config] secure(authpriv) 로그 설정 미흡
#   U_66_3 : [Config] messages(info) 로그 설정 미흡
#   U_66_4 : [Config] cron 로그 설정 미흡
#   U_66_5 : [Config] maillog(mail) 로그 설정 미흡

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-66] 정책에 따른 시스템 로깅 설정 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. 패키지 및 서비스 상태 점검 (U_66_1)
PKG_CHECK=$(rpm -qa | grep "^rsyslog-[0-9]")
SERVICE_ACTIVE=$(systemctl is-active rsyslog 2>/dev/null)

if [[ -z "$PKG_CHECK" ]] || [[ "$SERVICE_ACTIVE" != "active" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_66_1")
    echo -e "${RED}[취약]${NC} [System] rsyslog 서비스가 동작하지 않고 있습니다."
    if [[ -z "$PKG_CHECK" ]]; then
        echo -e "   -> 원인: rsyslog 패키지 미설치"
    else
        echo -e "   -> 원인: rsyslog 서비스 비활성화 (Current: $SERVICE_ACTIVE)"
    fi
    # 서비스가 안 돌면 설정 점검 의미가 없으므로 여기서 종료할 수도 있으나,
    # 설정 파일이라도 있는지 확인하기 위해 계속 진행
fi

# 2. 설정 파일 점검
CONF_FILE="/etc/rsyslog.conf"

if [[ -f "$CONF_FILE" ]]; then
    echo -e "${YELLOW}[정보]${NC} 설정 파일($CONF_FILE) 내용을 점검합니다."
    
    # 주석(#)을 제거한 설정 내용만 추출
    CLEAN_CONF=$(grep -v "^#" "$CONF_FILE")

    # 2-1. Secure 로그 (authpriv) -> /var/log/secure (U_66_2)
    # authpriv.* 또는 authpriv.none이 아닌 설정이 /var/log/secure로 가는지 확인
    # 간단히 "authpriv" 와 "/var/log/secure" 가 한 라인에 있는지 체크
    if echo "$CLEAN_CONF" | grep -q "authpriv.*" && echo "$CLEAN_CONF" | grep -q "/var/log/secure"; then
        : # 양호
    else
        # 정확한 매칭을 위해 egrep 사용 (authpriv.* 가 /var/log/secure 에 매핑되는지)
        if echo "$CLEAN_CONF" | grep -E "authpriv\.\*.*\/var\/log\/secure"; then
             : # 양호
        else
             VULN_STATUS=1
             VULN_FLAGS+=("U_66_2")
             echo -e "${RED}[취약]${NC} [Config] secure 로그(authpriv) 설정이 미흡합니다."
        fi
    fi

    # 2-2. Messages 로그 (info, global) -> /var/log/messages (U_66_3)
    # *.info;mail.none;authpriv.none;cron.none                /var/log/messages
    if echo "$CLEAN_CONF" | grep -q "/var/log/messages"; then
        # 파일 경로는 있는데, *.info 수준인지 확인
        if echo "$CLEAN_CONF" | grep -E "\*\.info.*\/var\/log\/messages"; then
            : # 양호
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_66_3")
            echo -e "${RED}[취약]${NC} [Config] messages 로그(*.info) 설정이 미흡합니다."
        fi
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_66_3")
        echo -e "${RED}[취약]${NC} [Config] messages 로그 파일 설정이 없습니다."
    fi

    # 2-3. Cron 로그 (cron) -> /var/log/cron (U_66_4)
    if echo "$CLEAN_CONF" | grep -E "cron\.\*.*\/var\/log\/cron"; then
        : # 양호
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_66_4")
        echo -e "${RED}[취약]${NC} [Config] cron 로그 설정이 미흡합니다."
    fi

    # 2-4. Maillog (mail) -> /var/log/maillog (U_66_5)
    if echo "$CLEAN_CONF" | grep -E "mail\.\*.*\/var\/log\/maillog"; then
        : # 양호
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_66_5")
        echo -e "${RED}[취약]${NC} [Config] maillog 로그 설정이 미흡합니다."
    fi

    if [[ $VULN_STATUS -eq 0 ]] || ([[ $VULN_STATUS -eq 1 ]] && [[ "${VULN_FLAGS[*]}" =~ "U_66_1" ]]); then
        # U_66_1(서비스 미구동)만 떴거나 아무것도 안 떴을 때 메시지 정리
        if [[ ! "${VULN_FLAGS[*]}" =~ "U_66_1" ]]; then
            echo -e "${GREEN}[양호]${NC} [Config] 주요 로그 파일 설정이 모두 확인되었습니다."
        fi
    fi

else
    # 설정 파일 자체가 없음
    VULN_STATUS=1
    # 설정 파일이 없으면 모든 Config 플래그를 다 띄우는 것이 맞음
    VULN_FLAGS+=("U_66_2" "U_66_3" "U_66_4" "U_66_5")
    echo -e "${RED}[취약]${NC} [Config] 설정 파일($CONF_FILE)을 찾을 수 없습니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (시스템 로깅 설정 적절)"
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
