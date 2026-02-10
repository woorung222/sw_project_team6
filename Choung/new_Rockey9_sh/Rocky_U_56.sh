#!/bin/bash

# [U-56] FTP 서비스 접근 제어 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.135-138
# 자동 조치 가능 유무 : 불가능 (수동 설정 필요)
# 플래그 설명:
#   U_56_1 : [Common] /etc/ftpusers 파일 소유자(root) 및 권한(640 이하) 미흡
#   U_56_2 : [vsFTP] userlist_enable=NO 시 ftpusers 파일 권한 미흡
#   U_56_3 : [vsFTP] userlist_enable=YES 시 user_list 파일 권한 미흡
#   U_56_4 : [ProFTP] UseFtpUsers on 시 ftpusers 파일 권한 미흡
#   U_56_5 : [ProFTP] UseFtpUsers off 시 설정 파일 권한 미흡 또는 Limit LOGIN 미설정

# --- 점검 로직 시작 ---

# 초기화
U_56_1=0
U_56_2=0
U_56_3=0
U_56_4=0
U_56_5=0

# FTP 패키지 확인
PKG_VSFTP=$(rpm -qa | grep "vsftpd")
PKG_PROFTP=$(rpm -qa | grep "proftpd")

# 패키지가 하나라도 있어야 점검 진행 (없으면 모두 0/양호)
if [[ -n "$PKG_VSFTP" ]] || [[ -n "$PKG_PROFTP" ]]; then

    # 1. [Common] 기본 ftpusers 파일 점검 (U_56_1)
    COMMON_FILE="/etc/ftpusers"
    if [[ -f "$COMMON_FILE" ]]; then
        OWNER=$(stat -c "%U" "$COMMON_FILE")
        PERM=$(stat -c "%a" "$COMMON_FILE")
        # 소유자 root, 권한 640 이하 아니면 취약
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
            U_56_1=1
        fi
    fi

    # 2. [vsFTP] 점검 (U_56_2, U_56_3)
    if [[ -n "$PKG_VSFTP" ]]; then
        VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
        # 설정 파일 경로 보정
        if [[ ! -f "$VSFTP_CONF" && -f "/etc/vsftpd.conf" ]]; then
            VSFTP_CONF="/etc/vsftpd.conf"
        fi

        if [[ -f "$VSFTP_CONF" ]]; then
            # userlist_enable 값 확인 (기본값 NO)
            USERLIST_ENABLE=$(grep -v "^#" "$VSFTP_CONF" 2>/dev/null | grep "userlist_enable" | awk -F= '{print $2}' | tr -d ' ' | tr 'a-z' 'A-Z')

            # Case 1: userlist_enable=NO (또는 미설정) -> ftpusers 점검 (U_56_2)
            if [[ "$USERLIST_ENABLE" != "YES" ]]; then
                VS_FILE="/etc/vsftpd/ftpusers"
                if [[ -f "$VS_FILE" ]]; then
                    OWNER=$(stat -c "%U" "$VS_FILE")
                    PERM=$(stat -c "%a" "$VS_FILE")
                    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
                        U_56_2=1
                    fi
                else
                    # 파일 없으면 취약
                    U_56_2=1
                fi
            # Case 2: userlist_enable=YES -> user_list 점검 (U_56_3)
            else
                VS_LIST="/etc/vsftpd/user_list"
                if [[ -f "$VS_LIST" ]]; then
                    OWNER=$(stat -c "%U" "$VS_LIST")
                    PERM=$(stat -c "%a" "$VS_LIST")
                    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
                        U_56_3=1
                    fi
                else
                    # 파일 없으면 취약
                    U_56_3=1
                fi
            fi
        else
            # 설정 파일 없으면 취약 처리
            U_56_2=1 
        fi
    fi

    # 3. [ProFTP] 점검 (U_56_4, U_56_5)
    if [[ -n "$PKG_PROFTP" ]]; then
        PROFTP_CONF="/etc/proftpd.conf"
        if [[ ! -f "$PROFTP_CONF" && -f "/etc/proftpd/proftpd.conf" ]]; then
            PROFTP_CONF="/etc/proftpd/proftpd.conf"
        fi

        if [[ -f "$PROFTP_CONF" ]]; then
            USE_FTPUSERS=$(grep -v "^#" "$PROFTP_CONF" 2>/dev/null | grep "UseFtpUsers" | awk '{print $2}' | tr 'a-z' 'A-Z')

            # Case 1: UseFtpUsers ON (또는 미설정) -> ftpusers 점검 (U_56_4)
            if [[ "$USE_FTPUSERS" != "OFF" ]]; then
                PRO_FILE="/etc/ftpusers"
                if [[ -f "$PRO_FILE" ]]; then
                    OWNER=$(stat -c "%U" "$PRO_FILE")
                    PERM=$(stat -c "%a" "$PRO_FILE")
                    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
                        U_56_4=1
                    fi
                fi
            # Case 2: UseFtpUsers OFF -> 설정파일 권한 및 Limit LOGIN 점검 (U_56_5)
            else
                # 설정 파일 권한 점검
                CONF_OWNER=$(stat -c "%U" "$PROFTP_CONF")
                CONF_PERM=$(stat -c "%a" "$PROFTP_CONF")
                if [[ "$CONF_OWNER" != "root" ]] || [[ "$CONF_PERM" -gt 640 ]]; then
                    U_56_5=1
                fi
                
                # Limit LOGIN 블록 확인 (대소문자 무시)
                if ! grep -iq "<Limit LOGIN>" "$PROFTP_CONF"; then
                    U_56_5=1
                fi
            fi
        else
            # 설정 파일 없으면 취약 처리
            U_56_4=1
        fi
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_56_1 -eq 1 ]] || [[ $U_56_2 -eq 1 ]] || [[ $U_56_3 -eq 1 ]] || [[ $U_56_4 -eq 1 ]] || [[ $U_56_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-56",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_56_1": $U_56_1,
      "U_56_2": $U_56_2,
      "U_56_3": $U_56_3,
      "U_56_4": $U_56_4,
      "U_56_5": $U_56_5
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
