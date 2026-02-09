#!/bin/bash

# [U-57] ftpusers 파일 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.139-140
# 자동 조치 가능 유무 : 불가능 (파일 내부 텍스트 수정)
# 플래그 설명:
#   U_57_1 : [Common] 기본 /etc/ftpusers 파일 내 root 계정 미포함
#   U_57_2 : [vsFTP] vsftpd 전용 ftpusers 파일 내 root 계정 미포함
#   U_57_3 : [vsFTP] user_list 파일 내 root 계정 미포함
#   U_57_4 : [ProFTP] ProFTP 전용 ftpusers 파일 내 root 계정 미포함
#   U_57_5 : [ProFTP] RootLogin off 설정 미흡

# --- 점검 로직 시작 ---

# 초기화
U_57_1=0
U_57_2=0
U_57_3=0
U_57_4=0
U_57_5=0

# 1. [Common] 기본 FTP-ftpusers 점검 (U_57_1)
# 패키지 설치 여부와 관계없이 시스템에 해당 파일이 존재하면 root 차단 여부 확인
COMMON_FTPUSERS="/etc/ftpusers"
# Rocky/RedHat 계열은 /etc/ftpusers가 일반적, 혹시 모를 /etc/ftpd/ftpusers도 체크
if [[ ! -f "$COMMON_FTPUSERS" ]] && [[ -f "/etc/ftpd/ftpusers" ]]; then
    COMMON_FTPUSERS="/etc/ftpd/ftpusers"
fi

if [[ -f "$COMMON_FTPUSERS" ]]; then
    # root 계정이 리스트에 있는지 확인 (주석 제외, 정확한 단어 매칭)
    if ! grep -v "^#" "$COMMON_FTPUSERS" | grep -qw "root"; then
        U_57_1=1
    fi
fi
# 파일이 없으면 양호로 간주 (참고 코드 기준)

# 2. [vsFTP] 점검 (U_57_2, U_57_3)
if rpm -qa | grep -q "vsftpd"; then
    
    # 2-1. vsFTP - ftpusers 점검 (U_57_2)
    VS_FTPUSERS="/etc/vsftpd/ftpusers"
    [[ ! -f "$VS_FTPUSERS" ]] && VS_FTPUSERS="/etc/vsftpd.ftpusers"
    
    if [[ -f "$VS_FTPUSERS" ]]; then
        if ! grep -v "^#" "$VS_FTPUSERS" | grep -qw "root"; then
            U_57_2=1
        fi
    fi
    # 파일이 없으면 양호로 간주

    # 2-2. vsFTP - user_list 점검 (U_57_3)
    VS_USERLIST="/etc/vsftpd/user_list"
    [[ ! -f "$VS_USERLIST" ]] && VS_USERLIST="/etc/vsftpd.user_list"
    
    if [[ -f "$VS_USERLIST" ]]; then
        if ! grep -v "^#" "$VS_USERLIST" | grep -qw "root"; then
            U_57_3=1
        fi
    fi
    # 파일이 없으면 양호로 간주
fi

# 3. [ProFTP] 점검 (U_57_4, U_57_5)
if rpm -qa | grep -q "proftpd"; then

    # 3-1. ProFTP - ftpusers 점검 (U_57_4)
    # ProFTP는 보통 /etc/ftpusers를 공유하지만, 별도 설정 확인
    PRO_FTPUSERS="/etc/ftpd/ftpusers" # ProFTP 예시 경로
    if [[ -f "$PRO_FTPUSERS" ]]; then
        if ! grep -v "^#" "$PRO_FTPUSERS" | grep -qw "root"; then
            U_57_4=1
        fi
    fi

    # 3-2. ProFTP - RootLogin 설정 점검 (U_57_5)
    PROFTP_CONF="/etc/proftpd.conf"
    [[ ! -f "$PROFTP_CONF" ]] && PROFTP_CONF="/etc/proftpd/proftpd.conf"

    if [[ -f "$PROFTP_CONF" ]]; then
        # RootLogin off 설정이 있는지 확인 (대소문자 무시)
        # grep 결과가 없으면(설정이 없거나 on이면) 취약
        # 참고 코드: ROOT_LOGIN_OFF=$(grep ... | grep -i "off") -> 없으면 취약
        if ! grep -v "^#" "$PROFTP_CONF" | grep -i "RootLogin" | grep -iq "off"; then
            U_57_5=1
        fi
    else
        # 설정 파일이 없으면 안전하다고 판단할 근거가 없으나, 참고 코드 기준으로는 파일 미존재시 양호 처리
        # 여기서는 파일이 없으면 패스 (0)
        :
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_57_1 -eq 1 ]] || [[ $U_57_2 -eq 1 ]] || [[ $U_57_3 -eq 1 ]] || [[ $U_57_4 -eq 1 ]] || [[ $U_57_5 -eq 1 ]]; then
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
    "flag_id": "U-57",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flags": {
      "U_57_1": $U_57_1,
      "U_57_2": $U_57_2,
      "U_57_3": $U_57_3,
      "U_57_4": $U_57_4,
      "U_57_5": $U_57_5
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
