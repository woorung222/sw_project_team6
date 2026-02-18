#!/usr/bin/env bash
set -u

# =========================================================
# U_37 (상) crontab 및 at 파일 접근 통제 | Ubuntu 24.04
# - 진단 기준: crontab/at 명령어의 SUID 설정 제거 여부 및 설정 파일 권한(640) 점검
# - Rocky 논리 반영:
#   U_37_1: crontab 명령어 SUID/Exec 권한 및 /etc/cron.* 파일 권한
#   U_37_2: at 명령어 SUID/Exec 권한 및 /etc/at.* 파일 권한
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_37"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
FLAG_U_37_1=0
FLAG_U_37_2=0

# -------------------------
# 1. [U_37_1] Cron 관련 점검
# -------------------------
# 1-1. crontab 명령어 권한 점검 (/usr/bin/crontab)
# Ansible 조치 기준(750)에 맞춰 SUID(4000)가 있거나 Others에 쓰기/실행 권한이 있으면 취약
CRON_BIN="/usr/bin/crontab"
if [ -f "$CRON_BIN" ]; then
    PERM=$(stat -c "%a" "$CRON_BIN")
    # 4000(SUID) 이상이거나, 마지막 자리(Others)가 0이 아니면 취약
    if [ "$PERM" -ge 4000 ] || [ $((PERM % 10)) -ne 0 ]; then
        FLAG_U_37_1=1
    fi
fi

# 1-2. cron 설정 파일 점검 (/etc/cron.allow, /etc/cron.deny)
for FILE in "/etc/cron.allow" "/etc/cron.deny"; do
    if [ -f "$FILE" ]; then
        OWNER=$(stat -c "%U" "$FILE")
        PERM=$(stat -c "%a" "$FILE")
        # 소유자가 root가 아니거나, 권한이 640보다 크면(예: 644) 취약
        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
            FLAG_U_37_1=1
        fi
    fi
done

# 1-3. cron 디렉터리 내 파일 점검
# /etc/cron.d, daily, hourly, monthly, weekly
CRON_DIRS="/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly"
for DIR in $CRON_DIRS; do
    if [ -d "$DIR" ]; then
        # root 소유가 아니거나 권한이 640 초과인 파일이 하나라도 있으면 취약
        if find "$DIR" -type f \( ! -user root -o -perm /027 \) -print -quit 2>/dev/null | grep -q .; then
            FLAG_U_37_1=1
        fi
    fi
done

# -------------------------
# 2. [U_37_2] At 관련 점검
# -------------------------
# 2-1. at 명령어 권한 점검 (/usr/bin/at)
AT_BIN="/usr/bin/at"
if [ -f "$AT_BIN" ]; then
    PERM=$(stat -c "%a" "$AT_BIN")
    # SUID 확인 및 Others 권한 확인
    if [ "$PERM" -ge 4000 ] || [ $((PERM % 10)) -ne 0 ]; then
        FLAG_U_37_2=1
    fi
fi

# 2-2. at 설정 파일 점검 (/etc/at.allow, /etc/at.deny)
for FILE in "/etc/at.allow" "/etc/at.deny"; do
    if [ -f "$FILE" ]; then
        OWNER=$(stat -c "%U" "$FILE")
        PERM=$(stat -c "%a" "$FILE")
        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
            FLAG_U_37_2=1
        fi
    fi
done

# -------------------------
# 3. VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_37_1" -eq 1 ] || [ "$FLAG_U_37_2" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_37_1": $FLAG_U_37_1,
      "U_37_2": $FLAG_U_37_2
    },
    "timestamp": "$DATE"
  }
}
EOF