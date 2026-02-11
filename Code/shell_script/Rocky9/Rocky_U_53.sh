#!/bin/bash

# [U-53] FTP 서비스 정보 노출 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.127-130
# 자동 조치 가능 유무 : 불가능 (배너 파일 생성 및 설정 편집)
# 플래그 설명:
#   U_53_1 : [vsFTP] ftpd_banner 설정 미흡 (패키지 설치 시)
#   U_53_2 : [ProFTP] ServerIdent 설정 미흡 (패키지 설치 시)

# --- 점검 로직 시작 ---

# 초기화
U_53_1=0
U_53_2=0

# 1. [vsFTP] 점검 (U_53_1)
if rpm -qa | grep -q "vsftpd"; then
    # 설정 파일 경로 확인
    VSFTP_CONF=""
    if [[ -f "/etc/vsftpd/vsftpd.conf" ]]; then
        VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    elif [[ -f "/etc/vsftpd.conf" ]]; then
        VSFTP_CONF="/etc/vsftpd.conf"
    fi

    if [[ -n "$VSFTP_CONF" ]]; then
        # ftpd_banner 설정 확인 (주석 제외)
        if ! grep -v "^#" "$VSFTP_CONF" 2>/dev/null | grep -q "ftpd_banner"; then
            U_53_1=1
        fi
    else
        # 패키지는 있는데 설정 파일이 없는 경우 (기본 설정 사용 시 버전 노출 가능성 높음)
        U_53_1=1
    fi
fi

# 2. [ProFTP] 점검 (U_53_2)
if rpm -qa | grep -q "proftpd"; then
    # 설정 파일 경로 확인
    PROFTP_CONF=""
    if [[ -f "/etc/proftpd.conf" ]]; then
        PROFTP_CONF="/etc/proftpd.conf"
    elif [[ -f "/etc/proftpd/proftpd.conf" ]]; then
        PROFTP_CONF="/etc/proftpd/proftpd.conf"
    fi

    if [[ -n "$PROFTP_CONF" ]]; then
        # ServerIdent 설정 확인 (주석 제외)
        if ! grep -v "^#" "$PROFTP_CONF" 2>/dev/null | grep -q "ServerIdent"; then
            U_53_2=1
        fi
    else
        # 설정 파일 없음
        U_53_2=1
    fi
fi

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_53_1 -eq 1 ]] || [[ $U_53_2 -eq 1 ]]; then
    IS_VUL=1
fi

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-53",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_53_1": $U_53_1,
      "U_53_2": $U_53_2
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
