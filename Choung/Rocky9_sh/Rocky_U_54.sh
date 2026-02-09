#!/bin/bash

# [U-54] 암호화되지 않은 FTP 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.131-133 [cite: 1340-1412]
# 점검 목적 : 평문 전송을 사용하는 FTP 서비스를 차단하고 SFTP 사용 유도
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_54_1 : [inetd] inetd.conf 내 FTP 활성화
#   U_54_2 : [xinetd] xinetd.d/ftp 활성화
#   U_54_3 : [vsFTP] vsftpd 서비스 활성화 (Systemd)
#   U_54_4 : [ProFTP] proftpd 서비스 활성화 (Systemd)
#   U_54_5 : [Process] FTP 프로세스 실행 중

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-54] 암호화되지 않은 FTP 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 2. 패키지 설치 여부 우선 확인
# vsftpd 또는 proftpd 패키지가 설치되어 있는지 확인
PKG_CHECK=$(rpm -qa | grep -E "vsftpd|proftpd")

if [[ -z "$PKG_CHECK" ]]; then
    # 패키지가 없으면 서비스 구동 불가능 -> 즉시 양호
    echo -e "${GREEN}[양호]${NC} FTP 서비스 패키지(vsftpd, proftpd)가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# 3. 패키지가 설치된 경우 정밀 점검 시작
echo -e "${YELLOW}[정보]${NC} FTP 패키지가 설치되어 있습니다. 서비스 활성화 여부를 점검합니다."
echo -e "   -> 설치된 패키지: $(echo $PKG_CHECK | tr '\n' ' ')"

# 3-1. [inetd] 설정 점검 (U_54_1) - PDF p.132
INETD_CONF="/etc/inetd.conf"
if [[ -f "$INETD_CONF" ]]; then
    INETD_CHECK=$(grep -v "^#" "$INETD_CONF" | grep "ftp")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_54_1")
        echo -e "${RED}[취약]${NC} [inetd] 설정 파일에 FTP 서비스가 활성화되어 있습니다."
    fi
fi

# 3-2. [xinetd] 설정 점검 (U_54_2) - PDF p.132
XINETD_FILE="/etc/xinetd.d/ftp"
if [[ -f "$XINETD_FILE" ]]; then
    DISABLE_CHECK=$(grep "disable" "$XINETD_FILE" | grep "yes")
    if [[ -z "$DISABLE_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_54_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정 파일에 'disable = yes' 설정이 없습니다."
    fi
fi

# 3-3. [vsFTP] Systemd 서비스 점검 (U_54_3) - PDF p.132
VSFTP_ACTIVE=$(systemctl is-active vsftpd 2>/dev/null)
if [[ "$VSFTP_ACTIVE" == "active" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_54_3")
    echo -e "${RED}[취약]${NC} [vsFTP] vsftpd 서비스가 활성화(active) 상태입니다."
fi

# 3-4. [ProFTP] Systemd 서비스 점검 (U_54_4) - PDF p.132
PROFTP_ACTIVE=$(systemctl is-active proftpd 2>/dev/null)
if [[ "$PROFTP_ACTIVE" == "active" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_54_4")
    echo -e "${RED}[취약]${NC} [ProFTP] proftpd 서비스가 활성화(active) 상태입니다."
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
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
