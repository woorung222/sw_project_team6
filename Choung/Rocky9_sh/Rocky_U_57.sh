#!/bin/bash

# [U-57] ftpusers 파일 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.139-140 (사용자 제공 Step 반영)
# 점검 목적 : FTP 서비스 접속 시 root 계정의 로그인을 설정에 따라 정확한 파일에서 차단하고 있는지 확인
# 자동 조치 가능 유무 : 불가능 (파일 내부 텍스트 수정)
# 플래그 설명:
#   U_57_1 : [vsFTP] userlist_enable=NO 일 때 ftpusers 파일 설정 미흡
#   U_57_2 : [vsFTP] userlist_enable=YES 일 때 user_list 파일 설정 미흡
#   U_57_3 : [ProFTP] UseFtpUsers=on 일 때 ftpusers 파일 설정 미흡
#   U_57_4 : [ProFTP] UseFtpUsers=off 일 때 RootLogin 설정 미흡

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-57] ftpusers 파일 설정 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 패키지 확인
PKG_VSFTP=$(rpm -qa | grep "vsftpd")
PKG_PROFTP=$(rpm -qa | grep "proftpd")

if [[ -z "$PKG_VSFTP" ]] && [[ -z "$PKG_PROFTP" ]]; then
    echo -e "${GREEN}[양호]${NC} FTP 서비스 패키지가 설치되어 있지 않습니다."
    echo "----------------------------------------------------------------"
    echo -e "결과: ${GREEN}[양호]${NC}"
    echo "Debug: Activated flag : {NULL}"
    echo "----------------------------------------------------------------"
    exit 0
fi

# ----------------------------------------------------------------
# 1. [vsFTP] 점검
# ----------------------------------------------------------------
if [[ -n "$PKG_VSFTP" ]]; then
    echo -e "${WARN}[정보]${NC} vsftpd 패키지 설치됨. 설정값에 따른 파일 점검을 시작합니다."
    
    # 설정 파일 찾기 (/etc/vsftpd.conf 또는 /etc/vsftpd/vsftpd.conf)
    if [[ -f "/etc/vsftpd/vsftpd.conf" ]]; then
        VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    elif [[ -f "/etc/vsftpd.conf" ]]; then
        VSFTP_CONF="/etc/vsftpd.conf"
    else
        echo -e "${RED}[취약]${NC} [vsFTP] 설정 파일을 찾을 수 없습니다."
        VULN_STATUS=1
        VULN_FLAGS+=("U_57_1") # 임시 플래그
    fi

    if [[ -f "$VSFTP_CONF" ]]; then
        # userlist_enable 값 확인 (소문자 변환 후 공백 제거)
        # 설정이 없으면 기본값 NO로 간주 (vsftpd 버전에 따라 다를 수 있으나 보통 NO)
        ENABLE_VAL=$(grep -v "^#" "$VSFTP_CONF" | grep "userlist_enable" | awk -F= '{print $2}' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
        
        echo -e "   -> userlist_enable 설정값: ${ENABLE_VAL:-no (default)}"

        # ----------------------------------------------------------------
        # CASE 1: userlist_enable = NO (또는 없음) -> ftpusers 파일 점검
        # ----------------------------------------------------------------
        if [[ "$ENABLE_VAL" != "yes" ]]; then
            # 점검 대상 파일: /etc/vsftpd/ftpusers, /etc/vsftpd.ftpusers, /etc/ftpusers
            FOUND_FILE=""
            for F in "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers" "/etc/ftpusers"; do
                if [[ -f "$F" ]]; then FOUND_FILE="$F"; break; fi
            done

            if [[ -n "$FOUND_FILE" ]]; then
                ROOT_CHECK=$(grep -v "^#" "$FOUND_FILE" | grep -w "root")
                if [[ -n "$ROOT_CHECK" ]]; then
                    echo -e "${GREEN}[양호]${NC} [vsFTP] $FOUND_FILE 파일에 root 계정이 등록되어 있습니다."
                else
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_57_1")
                    echo -e "${RED}[취약]${NC} [vsFTP] $FOUND_FILE 파일에 root 계정이 누락되었습니다."
                fi
            else
                VULN_STATUS=1
                VULN_FLAGS+=("U_57_1")
                echo -e "${RED}[취약]${NC} [vsFTP] ftpusers 파일을 찾을 수 없습니다."
            fi

        # ----------------------------------------------------------------
        # CASE 2: userlist_enable = YES -> user_list 파일 점검
        # ----------------------------------------------------------------
        else
            # 점검 대상 파일: /etc/vsftpd/user_list, /etc/vsftpd.user_list
            FOUND_FILE=""
            for F in "/etc/vsftpd/user_list" "/etc/vsftpd.user_list"; do
                if [[ -f "$F" ]]; then FOUND_FILE="$F"; break; fi
            done

            if [[ -n "$FOUND_FILE" ]]; then
                ROOT_CHECK=$(grep -v "^#" "$FOUND_FILE" | grep -w "root")
                
                # 추가 확인: userlist_deny 옵션 (YES여야 리스트에 있는 root가 차단됨)
                DENY_VAL=$(grep -v "^#" "$VSFTP_CONF" | grep "userlist_deny" | awk -F= '{print $2}' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
                DENY_VAL=${DENY_VAL:-yes} # 기본값 yes

                if [[ -n "$ROOT_CHECK" ]] && [[ "$DENY_VAL" == "yes" ]]; then
                    echo -e "${GREEN}[양호]${NC} [vsFTP] $FOUND_FILE 에 root가 있고 deny=YES로 설정되어 차단됩니다."
                elif [[ -z "$ROOT_CHECK" ]] && [[ "$DENY_VAL" == "no" ]]; then
                    # deny=NO(허용 리스트 모드)인데 root가 없으면 차단된 것임 (안전)
                    echo -e "${GREEN}[양호]${NC} [vsFTP] deny=NO(허용목록) 설정이며, 리스트에 root가 없어 안전합니다."
                else
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_57_2")
                    echo -e "${RED}[취약]${NC} [vsFTP] root 차단 설정 미흡 ($FOUND_FILE 내용 또는 userlist_deny=$DENY_VAL 확인 필요)"
                fi
            else
                VULN_STATUS=1
                VULN_FLAGS+=("U_57_2")
                echo -e "${RED}[취약]${NC} [vsFTP] user_list 파일을 찾을 수 없습니다."
            fi
        fi
    fi
fi

# ----------------------------------------------------------------
# 2. [ProFTP] 점검
# ----------------------------------------------------------------
if [[ -n "$PKG_PROFTP" ]]; then
    echo -e "${WARN}[정보]${NC} proftpd 패키지 설치됨. 설정값에 따른 점검을 시작합니다."
    
    # 설정 파일 찾기
    if [[ -f "/etc/proftpd/proftpd.conf" ]]; then
        PROFTP_CONF="/etc/proftpd/proftpd.conf"
    elif [[ -f "/etc/proftpd.conf" ]]; then
        PROFTP_CONF="/etc/proftpd.conf"
    else
        PROFTP_CONF=""
    fi

    if [[ -f "$PROFTP_CONF" ]]; then
        # UseFtpUsers 값 확인
        USE_FTPUSERS=$(grep -v "^#" "$PROFTP_CONF" | grep "UseFtpUsers" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
        echo -e "   -> UseFtpUsers 설정값: ${USE_FTPUSERS:-on (default)}"

        # ----------------------------------------------------------------
        # CASE 1: UseFtpUsers = ON (또는 없음) -> ftpusers 파일 점검
        # ----------------------------------------------------------------
        if [[ "$USE_FTPUSERS" != "off" ]]; then
            # 점검 대상 파일: /etc/ftpusers, /etc/ftpd/ftpusers
            FOUND_FILE=""
            for F in "/etc/ftpusers" "/etc/ftpd/ftpusers"; do
                if [[ -f "$F" ]]; then FOUND_FILE="$F"; break; fi
            done

            if [[ -n "$FOUND_FILE" ]]; then
                ROOT_CHECK=$(grep -v "^#" "$FOUND_FILE" | grep -w "root")
                if [[ -n "$ROOT_CHECK" ]]; then
                    echo -e "${GREEN}[양호]${NC} [ProFTP] $FOUND_FILE 파일에 root 계정이 등록되어 있습니다."
                else
                    VULN_STATUS=1
                    VULN_FLAGS+=("U_57_3")
                    echo -e "${RED}[취약]${NC} [ProFTP] $FOUND_FILE 파일에 root 계정이 누락되었습니다."
                fi
            else
                VULN_STATUS=1
                VULN_FLAGS+=("U_57_3")
                echo -e "${RED}[취약]${NC} [ProFTP] ftpusers 파일을 찾을 수 없습니다."
            fi
            
        # ----------------------------------------------------------------
        # CASE 2: UseFtpUsers = OFF -> RootLogin 점검
        # ----------------------------------------------------------------
        else
            ROOT_LOGIN=$(grep -v "^#" "$PROFTP_CONF" | grep -i "RootLogin" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
            
            if [[ "$ROOT_LOGIN" == "off" ]]; then
                echo -e "${GREEN}[양호]${NC} [ProFTP] RootLogin off 설정이 적용되어 있습니다."
            else
                VULN_STATUS=1
                VULN_FLAGS+=("U_57_4")
                echo -e "${RED}[취약]${NC} [ProFTP] RootLogin 설정이 off가 아닙니다. (현재값: ${ROOT_LOGIN:-미설정})"
            fi
        fi
    else
        echo -e "${RED}[취약]${NC} [ProFTP] 설정 파일을 찾을 수 없습니다."
        VULN_STATUS=1
        VULN_FLAGS+=("U_57_3")
    fi
fi

# ----------------------------------------------------------------
# 최종 결과 출력
# ----------------------------------------------------------------
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (설정에 따른 Root 접근 차단 완료)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
