#!/bin/bash

# [U-54] 암호화되지 않은 FTP 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.131-133
# 점검 목적 : 평문 전송을 사용하는 FTP 서비스를 차단하고 SFTP 사용 유도
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_54_1 : [inetd] inetd.conf 내 FTP 활성화
#   U_54_2 : [xinetd] xinetd.d/ftp 활성화
#   U_54_3 : [vsFTP] vsftpd 서비스 활성화 (Systemd)
#   U_54_4 : [ProFTP] proftpd 서비스 활성화 (Systemd)
#   U_54_5 : [Process] FTP 프로세스 실행 중

# --- 점검 로직 시작 ---

# 초기화
U_54_1=0
U_54_2=0
U_54_3=0
U_54_4=0
U_54_5=0

# 1. 패키지 설치 여부 확인
# vsftpd 또는 proftpd 패키지가 설치되어 있어야 서비스 구동 가능
if rpm -qa | grep -qE "vsftpd|proftpd"; then

    # 2. [inetd] 설정 점검 (U_54_1)
    if [[ -f "/etc/inetd.conf" ]]; then
        # 주석 제외하고 ftp 설정 확인
        if grep -v "^#" "/etc/inetd.conf" 2>/dev/null | grep -q "ftp"; then
            U_54_1=1
        fi
    fi

    # 3. [xinetd] 설정 점검 (U_54_2)
    if [[ -f "/etc/xinetd.d/ftp" ]]; then
        # disable = yes 설정이 없으면 취약
        if ! grep "disable" "/etc/xinetd.d/ftp" 2>/dev/null | grep -q "yes"; then
            U_54_2=1
        fi
    fi

    # 4. [vsFTP] Systemd 서비스 점검 (U_54_3)
    if systemctl is-active vsftpd >/dev/null 2>&1; then
        U_54_3=1
    fi

    # 5. [ProFTP] Systemd 서비스 점검 (U_54_4)
    if systemctl is-active proftpd >/dev/null 2>&1; then
        U_54_4=1
    fi

    # 6. [Process] 프로세스 점검 (U_54_5)
    # 실제 프로세스 실행 여부 확인 (ftpd, vsftpd, proftpd)
    if ps -ef | grep -v grep | grep -qE "vsftpd|proftpd|ftpd"; then
        U_54_5=1
    fi
fi

# 7. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_54_1 -eq 1 ]] || [[ $U_54_2 -eq 1 ]] || [[ $U_54_3 -eq 1 ]] || [[ $U_54_4 -eq 1 ]] || [[ $U_54_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 8. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-54",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_54_1": $U_54_1,
      "U_54_2": $U_54_2,
      "U_54_3": $U_54_3,
      "U_54_4": $U_54_4,
      "U_54_5": $U_54_5
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
