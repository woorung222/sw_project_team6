#!/bin/bash

# [U-24] 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이고, 타 사용자 쓰기 권한이 없는 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_24_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

# 점검할 환경변수 파일 목록
CHECK_FILES=".profile .cshrc .login .kshrc .bash_profile .bashrc .bash_logout .netrc .exrc"

# /etc/passwd 에서 사용자 정보 읽기 (사용자명:홈디렉터리)
# 시스템 계정도 쉘이 있고 홈이 있으면 점검하는 것이 원칙임
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    # 홈 디렉터리가 실제로 존재하는지 확인
    if [ -d "$HOMEDIR" ]; then
        for FILE in $CHECK_FILES; do
            TARGET="$HOMEDIR/$FILE"
            
            # 파일이 존재하는 경우에만 점검
            if [ -f "$TARGET" ]; then
                # 1. 소유자 확인
                FILE_OWNER=$(stat -c "%U" "$TARGET")
                
                # 소유자가 root도 아니고, 해당 계정(USERNAME)도 아니면 취약
                if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USERNAME" ]; then
                    U_24_1=1
                    # VULN_DETAILS+="[Owner] $TARGET($FILE_OWNER) " # 디버깅용
                fi

                # 2. 권한 확인 (Group, Other 쓰기 권한 확인)
                # %A 출력 예: -rw-r--r-- 
                # 5번째 문자(Group Write), 8번째 문자(Other Write) 확인
                PERM_STR=$(stat -c "%A" "$TARGET")
                
                # Group Write 확인
                if [ "${PERM_STR:5:1}" == "w" ]; then
                    U_24_1=1
                    # VULN_DETAILS+="[G-Write] $TARGET "
                fi
                
                # Other Write 확인
                if [ "${PERM_STR:8:1}" == "w" ]; then
                    U_24_1=1
                    # VULN_DETAILS+="[O-Write] $TARGET "
                fi
            fi
        done
    fi
done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_24_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-24",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_24_1": $U_24_1
    },
    "timestamp": "$DATE"
  }
}
EOF