#!/bin/bash

# [U-35] 공유 서비스 익명 접근 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.70-73
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_35_1 : [FTP] 기본 FTP 계정(ftp/anonymous) 존재 발견
#   U_35_2 : [vsFTP] vsftpd 익명 접속 허용 설정 발견
#   U_35_3 : [ProFTP] proftpd 익명 접속 설정 활성화 발견
#   U_35_4 : [NFS] exports 파일 내 익명 접근(anon) 옵션 설정 발견
#   U_35_5 : [Samba] smb.conf 내 익명 사용자 접근(guest ok) 허용 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-35] 공유 서비스 익명 접근 제한 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [FTP] 계정 점검 (U_35_1) - PDF p.72 
# 변수에 담아 [[ -n ]] 구문으로 안전하게 체크
FTP_ACC_CHECK=$(grep -E "^ftp:|^anonymous:" /etc/passwd)
if [[ -n "$FTP_ACC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_35_1")
    echo -e "${RED}[취약]${NC} [FTP] /etc/passwd 내 불필요한 FTP 계정이 발견되었습니다."
fi

# 2. [vsFTP] 설정 점검 (U_35_2) - PDF p.72 
VS_CONF="/etc/vsftpd/vsftpd.conf"
[[ ! -f "$VS_CONF" ]] && VS_CONF="/etc/vsftpd.conf"

if [[ -f "$VS_CONF" ]]; then
    # 주석 제외하고 anonymous_enable=YES 여부 확인
    VS_ANON_CHECK=$(grep -v "^#" "$VS_CONF" | grep -i "anonymous_enable" | grep -iw "YES")
    if [[ -n "$VS_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_35_2")
        echo -e "${RED}[취약]${NC} [vsFTP] vsftpd에서 익명 접속(anonymous_enable=YES)이 허용되어 있습니다."
    fi
fi

# 3. [ProFTP] 설정 점검 (U_35_3) - PDF p.72 
PRO_CONF="/etc/proftpd/proftpd.conf"
[[ ! -f "$PRO_CONF" ]] && PRO_CONF="/etc/proftpd.conf"

if [[ -f "$PRO_CONF" ]]; then
    # PDF 가이드: <Anonymous> 섹션 내 User/UserAlias 설정 여부 파싱 (p.73) [cite: 110]
    PRO_ANON_CHECK=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PRO_CONF" | grep -vE "^#" | grep -iE "User|UserAlias")
    if [[ -n "$PRO_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_35_3")
        echo -e "${RED}[취약]${NC} [ProFTP] proftpd에서 익명 접속 설정이 활성화되어 있습니다."
    fi
fi

# 4. [NFS] 설정 점검 (U_35_4) - PDF p.73 
if [[ -f "/etc/exports" ]]; then
    # PDF 가이드: anonuid 또는 anongid 옵션 확인 (p.73) [cite: 114, 121]
    NFS_ANON_CHECK=$(grep -v "^#" /etc/exports | grep -Ei "anonuid|anongid")
    if [[ -n "$NFS_ANON_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_35_4")
        echo -e "${RED}[취약]${NC} [NFS] /etc/exports 내 익명 접근 옵션(anonuid/anongid)이 설정되어 있습니다."
    fi
fi

# 5. [Samba] 설정 점검 (U_35_5) - PDF p.73 
if [[ -f "/etc/samba/smb.conf" ]]; then
    # PDF 가이드: guest ok 옵션 확인 (p.73) [cite: 124, 127]
    SAMBA_GUEST_CHECK=$(grep -v "^#" /etc/samba/smb.conf | grep -i "guest ok" | grep -iw "yes")
    if [[ -n "$SAMBA_GUEST_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_35_5")
        echo -e "${RED}[취약]${NC} [Samba] smb.conf 내 익명 접근(guest ok = yes)이 허용되어 있습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} 모든 공유 서비스의 익명 접근이 가이드라인에 따라 적절히 제한되어 있습니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력 (정렬 및 중복 제거 적용)
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -V | uniq | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
