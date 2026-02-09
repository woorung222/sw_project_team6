#!/bin/bash

# [U-55] FTP 계정 shell 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.134
# 점검 목적 : FTP 기본 계정(ftp)의 대화형 로그인 차단
# 자동 조치 가능 유무 : 가능 (usermod 명령어 사용)
# 플래그 설명:
#   U_55_1 : [Account] ftp 계정에 로그인 가능한 쉘(/bin/bash 등)이 부여됨

# --- 점검 로직 시작 ---

# 초기화
U_55_1=0

# 1. ftp 계정 존재 여부 확인
FTP_ENTRY=$(grep "^ftp:" /etc/passwd)

if [[ -n "$FTP_ENTRY" ]]; then
    # 2. 쉘 설정 확인
    USER_SHELL=$(echo "$FTP_ENTRY" | awk -F: '{print $7}')

    # 3. 로그인 불가 쉘 목록 비교 (/bin/false, /sbin/nologin, /usr/sbin/nologin)
    # 해당 쉘들이 아니면(로그인 가능한 쉘이면) 취약
    if [[ "$USER_SHELL" != "/bin/false" ]] && \
       [[ "$USER_SHELL" != "/sbin/nologin" ]] && \
       [[ "$USER_SHELL" != "/usr/sbin/nologin" ]]; then
        U_55_1=1
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=$U_55_1

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-55",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_55_1": $U_55_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
