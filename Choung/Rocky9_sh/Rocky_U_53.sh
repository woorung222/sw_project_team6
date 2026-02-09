#!/bin/bash

# [U-53] FTP 서비스 정보 노출 제한
# 대상 운영체제 : Rocky Linux 9
# [cite_start]가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.127-130 [cite: 1240-1339]
# 점검 목적 : FTP 접속 배너를 통한 시스템 및 서비스 버전 정보 노출 방지
# 자동 조치 가능 유무 : 불가능 (배너 파일 생성 및 설정 편집)
# 플래그 설명:
#   U_53_1 : [vsFTP] ftpd_banner 설정 미흡
#   U_53_2 : [ProFTP] ServerIdent 설정 미흡

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-53] FTP 서비스 정보 노출 제한 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# FTP 관련 패키지 설치 여부 확인
# vsftpd 또는 proftpd가 하나라도 있는지 확인
PKG_VSFTP=$(rpm -qa | grep "vsftpd")
PKG_PROFTP=$(rpm -qa | grep "proftpd")

# 1. 패키지 설치 여부 판단 (설치되지 않았으면 바로 양호 종료)
if [[ -z "$PKG_VSFTP" ]] && [[ -z "$PKG_PROFTP" ]]; then
    echo -e "${GREEN}[양호]${NC} FTP 서비스(vsftpd, proftpd)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 2. [vsFTP] 설정 점검 (패키지가 있는 경우에만 수행)
if [[ -n "$PKG_VSFTP" ]]; then
    echo -e "${WARN}[정보]${NC} vsftpd 패키지가 설치되어 있습니다. 설정을 점검합니다."
    
    # 설정 파일 경로 확인
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    if [[ ! -f "$VSFTP_CONF" && -f "/etc/vsftpd.conf" ]]; then
        VSFTP_CONF="/etc/vsftpd.conf"
    fi

    if [[ -f "$VSFTP_CONF" ]]; then
        # ftpd_banner 설정 확인 (주석 제외)
        BANNER_CHECK=$(grep -v "^#" "$VSFTP_CONF" | grep "ftpd_banner")
        
        if [[ -n "$BANNER_CHECK" ]]; then
            echo -e "${GREEN}[양호]${NC} [vsFTP] 배너 정보가 설정되어 있습니다: $BANNER_CHECK"
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_53_1")
            echo -e "${RED}[취약]${NC} [vsFTP] 'ftpd_banner' 설정이 없어 기본 버전 정보가 노출될 수 있습니다."
        fi
    else
        # 패키지는 있는데 설정 파일이 없는 경우 (특이 케이스)
        echo -e "${WARN}[정보]${NC} [vsFTP] 설정 파일을 찾을 수 없습니다."
    fi
fi

# 3. [ProFTP] 설정 점검 (패키지가 있는 경우에만 수행)
if [[ -n "$PKG_PROFTP" ]]; then
    echo -e "${WARN}[정보]${NC} proftpd 패키지가 설치되어 있습니다. 설정을 점검합니다."
    
    PROFTP_CONF="/etc/proftpd.conf"
    if [[ ! -f "$PROFTP_CONF" && -f "/etc/proftpd/proftpd.conf" ]]; then
        PROFTP_CONF="/etc/proftpd/proftpd.conf"
    fi

    if [[ -f "$PROFTP_CONF" ]]; then
        # ServerIdent 설정 확인
        IDENT_CHECK=$(grep -v "^#" "$PROFTP_CONF" | grep "ServerIdent")
        
        if [[ -n "$IDENT_CHECK" ]]; then
            echo -e "${GREEN}[양호]${NC} [ProFTP] ServerIdent 설정이 존재합니다: $IDENT_CHECK"
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_53_2")
            echo -e "${RED}[취약]${NC} [ProFTP] 'ServerIdent' 설정이 없어 버전 정보가 노출될 수 있습니다."
        fi
    else
        echo -e "${WARN}[정보]${NC} [ProFTP] 설정 파일을 찾을 수 없습니다."
    fi
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (FTP 배너 설정 안전)"
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
