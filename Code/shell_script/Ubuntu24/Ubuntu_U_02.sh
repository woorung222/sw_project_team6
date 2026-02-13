#!/usr/bin/env bash
set -u

# =========================================================
# U_02 (상) 비밀번호 관리정책 설정 | Ubuntu 24.04
# - 진단 기준: 패스워드 복잡성, 사용기간(최대 90일, 최소 1일) 설정 여부
# - DB Desc: 패스워드 복잡성, 사용기간, 기억 설정 미흡
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_02"
CATEGORY="account"
IS_AUTO=1 # 관리자 동의 하에 자동 조치 가능

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_02_1=1

# -------------------------
# Evidence
# -------------------------
PAM_PWQUALITY="not_set"
MINLEN="not_set"
CREDITS="not_set"
PERIOD_OK=0

# -------------------------
# 1) PAM 적용 여부 점검
# -------------------------
PAM_FILE="/etc/pam.d/common-password"
if [ -f "$PAM_FILE" ]; then
  if grep -v '^\s*#' "$PAM_FILE" 2>/dev/null | grep -qE '\bpam_pwquality\.so\b|\bpam_pwquality\b'; then
    PAM_PWQUALITY="set"
  fi
fi

# -------------------------
# 2) pwquality 설정 점검 (복잡성)
# -------------------------
CONF="/etc/security/pwquality.conf"
if [ -f "$CONF" ]; then
  # minlen
  ML="$(grep -E '^\s*minlen\s*=' "$CONF" 2>/dev/null | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${ML:-}" ]; then
    MINLEN="$ML"
  fi

  # credits or minclass
  if grep -Eq '^\s*(dcredit|ucredit|lcredit|ocredit|minclass)\s*=' "$CONF" 2>/dev/null; then
    CREDITS="set"
  fi
fi

# -------------------------
# 3) 사용 기간 점검 (login.defs) - [추가된 로직]
# - PASS_MAX_DAYS 90 이하
# - PASS_MIN_DAYS 1 이상
# -------------------------
LOGIN_DEFS="/etc/login.defs"
MAX_DAYS=""
MIN_DAYS=""

if [ -f "$LOGIN_DEFS" ]; then
    MAX_DAYS=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | grep -v "^#" | awk '{print $2}')
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" "$LOGIN_DEFS" | grep -v "^#" | awk '{print $2}')
fi

CHECK_MAX=0
CHECK_MIN=0

# Max Days Check
if [ -n "$MAX_DAYS" ] && [ "$MAX_DAYS" -le 90 ]; then
    CHECK_MAX=1
fi

# Min Days Check
if [ -n "$MIN_DAYS" ] && [ "$MIN_DAYS" -ge 1 ]; then
    CHECK_MIN=1
fi

if [ "$CHECK_MAX" -eq 1 ] && [ "$CHECK_MIN" -eq 1 ]; then
    PERIOD_OK=1
fi

# -------------------------
# 4) 판정
# 양호: PAM 적용 + minlen>=8 + 복잡도 설정 + 기간 설정(Max<=90, Min>=1)
# -------------------------
OK_MINLEN=0
if [ "$MINLEN" != "not_set" ] 2>/dev/null; then
  if [[ "$MINLEN" =~ ^[0-9]+$ ]] && [ "$MINLEN" -ge 8 ]; then
    OK_MINLEN=1
  fi
fi

# 복잡성(PAM, Minlen, Credits) AND 사용기간(Period) 모두 만족해야 양호
if [ "$PAM_PWQUALITY" = "set" ] && [ "$OK_MINLEN" -eq 1 ] && [ "$CREDITS" = "set" ] && [ "$PERIOD_OK" -eq 1 ]; then
  FLAG_U_02_1=0
else
  FLAG_U_02_1=1
fi

# -------------------------
# 5) Output
# -------------------------
IS_VUL=$FLAG_U_02_1

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
      "U_02_1": $FLAG_U_02_1
    },
    "timestamp": "$DATE"
  }
}
EOF