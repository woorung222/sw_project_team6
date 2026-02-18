#!/usr/bin/env bash
set -u

# =========================================================
# U_07 (상) 불필요한 계정 제거 | Ubuntu 24.04
# - 진단 기준: 불필요한 기본 계정 및 장기 미사용 계정 존재 여부
# - Rocky 논리 반영:
#   U_07_1: lp, uucp, games, gopher, ftp, news 계정 존재 여부
#   U_07_2: 90일 이상 미사용 계정 (UID 1000 이상) 존재 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_07"
CATEGORY="account"
IS_AUTO=0  # 계정 삭제는 위험하므로 수동 조치(0)

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
FLAG_U_07_1=0
FLAG_U_07_2=0

# -------------------------
# 1) [U_07_1] 불필요한 기본 계정 점검
# -------------------------
UNNECESSARY_ACCOUNTS=("lp" "uucp" "games" "gopher" "ftp" "news")
DETECTED_ACC=0

for ACCT in "${UNNECESSARY_ACCOUNTS[@]}"; do
    if grep -q "^$ACCT:" /etc/passwd; then
        DETECTED_ACC=1
        break
    fi
done

if [ "$DETECTED_ACC" -eq 1 ]; then
    FLAG_U_07_1=1
else
    FLAG_U_07_1=0
fi

# -------------------------
# 2) [U_07_2] 장기 미사용 계정 점검 (90일)
# -------------------------
IDLE_LIMIT_DAYS=90
LONG_IDLE_FOUND=0

# lastlog -b 옵션 활용 (Rocky와 동일 논리)
# Ubuntu에서도 lastlog가 기본 제공됨. 없을 경우 대비 로직 포함 가능하나 표준환경 가정.
if command -v lastlog >/dev/null 2>&1; then
    # 90일 이상 접속 안 한 계정 목록 추출
    CHECK_IDLE=$(lastlog -b $IDLE_LIMIT_DAYS 2>/dev/null | awk '{print $1}' | tail -n +2)
    
    if [ -n "$CHECK_IDLE" ]; then
        for usr in $CHECK_IDLE; do
            # UID 1000 이상인 일반 계정인지 확인
            if id "$usr" >/dev/null 2>&1; then
                curr_uid=$(id -u "$usr")
                if [ "$curr_uid" -ge 1000 ] && [ "$usr" != "nobody" ]; then
                    LONG_IDLE_FOUND=1
                    break
                fi
            fi
        done
    fi
fi

if [ "$LONG_IDLE_FOUND" -eq 1 ]; then
    FLAG_U_07_2=1
else
    FLAG_U_07_2=0
fi

# -------------------------
# 3) VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_07_1" -eq 1 ] || [ "$FLAG_U_07_2" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# 4) Output (JSON)
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
      "U_07_1": $FLAG_U_07_1,
      "U_07_2": $FLAG_U_07_2
    },
    "timestamp": "$DATE"
  }
}
EOF