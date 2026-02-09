#!/bin/bash

# [U-37] crontab 설정파일 권한 설정 미흡
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.80-81
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_37_1 : [Cron] crontab 명령어 SUID 설정 또는 설정 파일(crontab/cron.allow 등) 권한 취약
#   U_37_2 : [At] at 명령어 SUID 설정 또는 설정 파일(at.allow 등) 권한 취약

# --- 점검 로직 시작 ---

# 초기화
U_37_1=0 # Cron 관련 (명령어 + 설정파일)
U_37_2=0 # At 관련 (명령어 + 설정파일)

# 1-1. [crontab 명령어] 점검 -> U_37_1 반영
CRON_BIN="/usr/bin/crontab"
if [[ -f "$CRON_BIN" ]]; then
    BIN_PERM=$(stat -c "%a" "$CRON_BIN")
    # SUID(4xxx)가 있거나, Others 권한에 실행(1)이 있는 경우 취약
    if [[ "$BIN_PERM" -ge 4000 ]] || [[ $((BIN_PERM % 10 % 2)) -eq 1 ]]; then
        U_37_1=1
    fi
fi

# 1-2. [cron 설정 파일] 점검 -> U_37_1 반영
# 단일 파일 점검 리스트
CHECK_LIST=("/etc/crontab" "/etc/cron.allow" "/etc/cron.deny" "/var/spool/cron")
for file in "${CHECK_LIST[@]}"; do
    if [[ -f "$file" ]]; then
        OWNER=$(stat -c "%U" "$file")
        PERM=$(stat -c "%a" "$file")
        # 소유자 root 아님 OR 권한 640 초과
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
            U_37_1=1
        fi
    elif [[ -d "$file" ]]; then
        # 디렉터리인 경우 (/var/spool/cron 등) 내부 파일 점검
        if find "$file" -type f \( ! -user root -o -perm /027 \) -print -quit 2>/dev/null | grep -q .; then
            U_37_1=1
        fi
    fi
done

# 디렉터리 내부 파일 전수 조사
CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
for dir in "${CRON_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # root가 아니거나, 권한이 640보다 개방된 파일 찾기
        if find "$dir" -type f \( ! -user root -o -perm /027 \) -print -quit 2>/dev/null | grep -q .; then
            U_37_1=1
        fi
    fi
done

# 2-1. [at 명령어] 점검 -> U_37_2 반영
AT_BIN="/usr/bin/at"
if [[ -f "$AT_BIN" ]]; then
    BIN_PERM=$(stat -c "%a" "$AT_BIN")
    if [[ "$BIN_PERM" -ge 4000 ]] || [[ $((BIN_PERM % 10 % 2)) -eq 1 ]]; then
        U_37_2=1
    fi
fi

# 2-2. [at 설정 파일] 점검 -> U_37_2 반영
AT_FILES=("/etc/at.allow" "/etc/at.deny")
for file in "${AT_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        OWNER=$(stat -c "%U" "$file")
        PERM=$(stat -c "%a" "$file")
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
            U_37_2=1
        fi
    fi
done

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_37_1 -eq 1 ]] || [[ $U_37_2 -eq 1 ]]; then
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
    "flag_id": "U-37",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_37_1": $U_37_1,
      "U_37_2": $U_37_2
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
