#!/bin/bash

# [U-24] 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이고, 타 사용자 쓰기 권한이 없는 경우 양호

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_24_1=0 
IS_VUL=0
IS_AUTO=1 

# 점검할 환경변수 파일 목록
CHECK_FILES=".profile .cshrc .login .kshrc .bash_profile .bashrc .bash_logout .netrc .exrc"

# /etc/passwd 기반 전수 점검
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    if [ -d "$HOMEDIR" ]; then
        for FILE in $CHECK_FILES; do
            TARGET="$HOMEDIR/$FILE"
            if [ -f "$TARGET" ]; then
                FILE_OWNER=$(stat -c "%U" "$TARGET")
                # 소유자 체크: root 또는 해당 사용자 계정
                if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USERNAME" ]; then
                    U_24_1=1
                fi
                # 권한 체크: Others 쓰기(w) 권한 존재 여부
                if [ "$(stat -c "%A" "$TARGET" | cut -c 9)" == "w" ]; then
                    U_24_1=1
                fi
            fi
        done
    fi
done < /etc/passwd

IS_VUL=$U_24_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-24",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_24_1": $U_24_1 },
    "timestamp": "$DATE"
  }
}
EOF