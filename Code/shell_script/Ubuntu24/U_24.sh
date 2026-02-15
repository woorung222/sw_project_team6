#!/usr/bin/env bash
set -u

# =========================================================
# U_24 (상) 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 홈 디렉터리 환경파일 소유자(root/계정) 및 타인 쓰기 금지
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_24"
CATEGORY="file"
IS_AUTO=1

U_24_1=0
CHECK_FILES=".profile .bashrc .bash_logout .bash_profile .kshrc .cshrc .login .netrc .exrc"

# 시스템 내 모든 실제 사용자의 홈 디렉터리 점검
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    if [ -d "$HOMEDIR" ] && [[ "$HOMEDIR" == /home/* || "$HOMEDIR" == "/root" ]]; then
        for FILE in $CHECK_FILES; do
            TARGET="$HOMEDIR/$FILE"
            if [ -f "$TARGET" ]; then
                OWNER=$(stat -c "%U" "$TARGET")
                PERM_STR=$(stat -c "%A" "$TARGET")
                
                # 소유자 미흡 또는 Others 쓰기 권한 발견 시 취약
                if [[ "$OWNER" != "root" && "$OWNER" != "$USERNAME" ]] || [[ "${PERM_STR:8:1}" == "w" ]]; then
                    U_24_1=1
                    break 2
                fi
            fi
        done
    fi
done < /etc/passwd

IS_VUL=$U_24_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_24_1": $U_24_1 },
    "timestamp": "$DATE"
  }
}
EOF