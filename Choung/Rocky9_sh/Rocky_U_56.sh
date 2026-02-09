#!/bin/bash

# [U-56] FTP 서비스 접근 제어 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.135-138 [cite: 1437-1515]
# 점검 목적 : FTP 접근 제어 파일의 권한 관리 및 접근 제어 설정 여부 확인
# 자동 조치 가능 유무 : 불가능 (가능은 하나, 왠만해서는 허용 IP/User 로직 판단 및 파일 편집)
# 플래그 설명:
#   U_56_1 : [Common] /etc/ftpusers 파일 소유자(root) 및 권한(640 이하) 미흡
#   U_56_2 : [vsFTP] userlist_enable=NO 시 ftpusers 파일 권한 미흡
#   U_56_3 : [vsFTP] userlist_enable=YES 시 user_list 파일 권한 미흡 또는 deny 설정 미흡
#   U_56_4 : [ProFTP] UseFtpUsers on 시 ftpusers 파일 권한 미흡
#   U_56_5 : [ProFTP] UseFtpUsers off 시 설정 파일 권한 미흡 또는 Limit LOGIN 미설정

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-56] FTP 서비스 접근 제어 설정 점검 시작"
echo "----------------------------------------------------------------"

# 1. Root 권한 체크
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# FTP 패키지 확인
PKG_VSFTP=$(rpm -qa | grep "vsftpd")
PKG_PROFTP=$(rpm -qa | grep "proftpd")

# 패키지가 없으면 양호
if [[ -z "$PKG_VSFTP" ]] && [[ -z "$PKG_PROFTP" ]]; then
    echo -e "${GREEN}[양호]${NC} FTP 서비스 패키지가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# ----------------------------------------------------------------
# 1. [Common] 기본 ftpusers 파일 점검 (U_56_1) - PDF p.135
# ----------------------------------------------------------------
# /etc/ftpusers 파일이 존재하면 무조건 점검 (공통 사항)
COMMON_FILE="/etc/ftpusers"
if [[ -f "$COMMON_FILE" ]]; then
    OWNER=$(stat -c "%U" "$COMMON_FILE")
    PERM=$(stat -c "%a" "$COMMON_FILE")
    
    # 소유자 root, 권한 640 이하(640, 600, 400 등)
    if [[ "$OWNER" == "root" ]] && [[ "$PERM" -le 640 ]]; then
        echo -e "${GREEN}[양호]${NC} [Common] $COMMON_FILE 소유자 및 권한이 적절합니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_56_1")
        echo -e "${RED}[취약]${NC} [Common] $COMMON_FILE 권한 설정이 미흡합니다. (Owner: $OWNER, Perm: $PERM)"
        echo -e "   -> 권고: 소유자 root, 권한 640 이하"
    fi
fi

# ----------------------------------------------------------------
# 2. [vsFTP] 점검 (U_56_2, U_56_3) - PDF p.136
# ----------------------------------------------------------------
if [[ -n "$PKG_VSFTP" ]]; then
    echo -e "${WARN}[정보]${NC} vsftpd 패키지 설치됨. 상세 설정 점검 중..."
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    
    if [[ -f "$VSFTP_CONF" ]]; then
        # userlist_enable 값 확인 (기본값 NO)
        USERLIST_ENABLE=$(grep -v "^#" "$VSFTP_CONF" | grep "userlist_enable" | awk -F= '{print $2}' | tr -d ' ')
        
        # Case 1: userlist_enable=NO (또는 미설정) -> ftpusers 파일 점검 (U_56_2)
        if [[ "$USERLIST_ENABLE" != "YES" ]]; then
            VS_FILE="/etc/vsftpd/ftpusers"
            if [[ -f "$VS_FILE" ]]; then
                OWNER=$(stat -c "%U" "$VS_FILE")
                PERM=$(stat -c "%a" "$VS_FILE")
                if [[ "$OWNER" == "root" ]] && [[ "$PERM" -le 640 ]]; then
                    echo -e "${GREEN}[양호]${NC} [vsFTP] userlist_enable=NO, $VS_FILE 권한 적절."
                else
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_56_2")
                    echo -e "${RED}[취약]${NC} [vsFTP] $VS_FILE 소유자/권한 미흡 (Owner: $OWNER, Perm: $PERM)"
                fi
            else
                # 파일이 없으면 취약으로 간주 (접근 제어 불가)
                VULN_STATUS=1
                VULN_FLAGS+=("U_56_2")
                echo -e "${RED}[취약]${NC} [vsFTP] userlist_enable=NO 상태이나 $VS_FILE 파일이 없습니다."
            fi
            
        # Case 2: userlist_enable=YES -> user_list 파일 및 deny 옵션 점검 (U_56_3)
        else
            VS_LIST="/etc/vsftpd/user_list"
            # 파일 권한 점검
            if [[ -f "$VS_LIST" ]]; then
                OWNER=$(stat -c "%U" "$VS_LIST")
                PERM=$(stat -c "%a" "$VS_LIST")
                if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_56_3")
                    echo -e "${RED}[취약]${NC} [vsFTP] $VS_LIST 소유자/권한 미흡 (Owner: $OWNER, Perm: $PERM)"
                fi
            else
                 VULN_STATUS=1
                 VULN_FLAGS+=("U_56_3")
                 echo -e "${RED}[취약]${NC} [vsFTP] userlist_enable=YES 상태이나 $VS_LIST 파일이 없습니다."
            fi
            
            # userlist_deny 옵션 점검 (YES=차단, NO=허용) - PDF p.136 하단
            # 명시적 설정이 없으면 기본값(YES)이므로, 파일만 잘 관리되면 양호로 볼 수도 있으나
            # 접근 제어 정책 확인 차원에서 출력
            DENY_VAL=$(grep -v "^#" "$VSFTP_CONF" | grep "userlist_deny" | awk -F= '{print $2}' | tr -d ' ')
            echo -e "${WARN}[정보]${NC} [vsFTP] userlist_deny 설정값: ${DENY_VAL:-YES(Default)}"
        fi
    fi
fi

# ----------------------------------------------------------------
# 3. [ProFTP] 점검 (U_56_4, U_56_5) - PDF p.137-138
# ----------------------------------------------------------------
if [[ -n "$PKG_PROFTP" ]]; then
    echo -e "${WARN}[정보]${NC} proftpd 패키지 설치됨. 상세 설정 점검 중..."
    PROFTP_CONF="/etc/proftpd.conf"
    
    if [[ -f "$PROFTP_CONF" ]]; then
        USE_FTPUSERS=$(grep -v "^#" "$PROFTP_CONF" | grep "UseFtpUsers" | awk '{print $2}')
        
        # Case 1: UseFtpUsers on (또는 미설정, 기본값 on) -> ftpusers 파일 점검 (U_56_4)
        if [[ "$USE_FTPUSERS" != "off" ]]; then
            # PDF에는 /etc/ftpusers 또는 /etc/ftpd/ftpusers 확인
            PRO_FILE="/etc/ftpusers"
            if [[ -f "$PRO_FILE" ]]; then
                OWNER=$(stat -c "%U" "$PRO_FILE")
                PERM=$(stat -c "%a" "$PRO_FILE")
                if [[ "$OWNER" == "root" ]] && [[ "$PERM" -le 640 ]]; then
                    echo -e "${GREEN}[양호]${NC} [ProFTP] UseFtpUsers on, $PRO_FILE 권한 적절."
                else
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_56_4")
                    echo -e "${RED}[취약]${NC} [ProFTP] $PRO_FILE 소유자/권한 미흡 (Owner: $OWNER, Perm: $PERM)"
                fi
            fi
            
        # Case 2: UseFtpUsers off -> 설정 파일 권한 및 <Limit LOGIN> 점검 (U_56_5)
        else
            # 설정 파일 자체 권한 점검
            CONF_OWNER=$(stat -c "%U" "$PROFTP_CONF")
            CONF_PERM=$(stat -c "%a" "$PROFTP_CONF")
            
            if [[ "$CONF_OWNER" != "root" ]] || [[ "$CONF_PERM" -gt 640 ]]; then
                VULN_STATUS=1
                VULN_FLAGS+=("U_56_5")
                echo -e "${RED}[취약]${NC} [ProFTP] 설정 파일($PROFTP_CONF) 권한 미흡"
            fi
            
            # Limit LOGIN 블록 확인
            LIMIT_CHECK=$(grep -i "<Limit LOGIN>" "$PROFTP_CONF")
            if [[ -z "$LIMIT_CHECK" ]]; then
                VULN_STATUS=1
                # 중복 플래그 방지
                if [[ ! "${VULN_FLAGS[*]}" =~ "U_56_5" ]]; then
                     VULN_FLAGS+=("U_56_5")
                fi
                echo -e "${RED}[취약]${NC} [ProFTP] <Limit LOGIN> 접근 제어 설정이 없습니다."
            fi
        fi
    fi
fi

# ----------------------------------------------------------------
# 최종 결과 출력
# ----------------------------------------------------------------
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (FTP 접근 제어 파일 및 설정 안전)"
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
