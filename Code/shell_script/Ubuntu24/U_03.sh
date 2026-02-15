#!/usr/bin/env bash
set -u

# =========================================================
# U_03 (상) 계정 잠금 임계값 설정 | Ubuntu 24.04
# - 진단 기준: faillock(authselect) 임계값 설정 여부 (DB U_03_3 매핑)
# - Rocky/DB 와의 통일성:
#   U_03_1 (pam_tally) : Ubuntu 24 사용 안 함 -> 0 (양호/해당없음)
#   U_03_2 (pam_tally2): Ubuntu 24 사용 안 함 -> 0 (양호/해당없음)
#   U_03_3 (faillock)  : Ubuntu 24 표준 -> 점검 대상
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_03"
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
# Ubuntu 24.04는 tally/tally2를 쓰지 않으므로 해당 없음(0) 처리
FLAG_U_03_1=0
FLAG_U_03_2=0
FLAG_U_03_3=1 # faillock 기본은 취약으로 가정하고 점검 시작

# -------------------------
# Evidence (내부 판단용)
# -------------------------
FA_LOCK_MODULE="not_set"
DENY_VAL="not_set"
UNLOCK_TIME_VAL="not_set"

# -------------------------
# Helper: 주석 제거
# -------------------------
strip_comments() {
  grep -vE '^\s*#' | grep -vE '^\s*$'
}

# -------------------------
# 1) PAM faillock 적용 여부 확인 (common-auth / common-account)
# -------------------------
PAM_AUTH="/etc/pam.d/common-auth"
PAM_ACCT="/etc/pam.d/common-account"
HAS_FAILLOCK=0

if [ -f "$PAM_AUTH" ]; then
  if strip_comments < "$PAM_AUTH" 2>/dev/null | grep -qE '\bpam_faillock\.so\b'; then
    HAS_FAILLOCK=1
  fi
fi
if [ -f "$PAM_ACCT" ]; then
  if strip_comments < "$PAM_ACCT" 2>/dev/null | grep -qE '\bpam_faillock\.so\b'; then
    HAS_FAILLOCK=1
  fi
fi

if [ "$HAS_FAILLOCK" -eq 1 ]; then
  FA_LOCK_MODULE="set"
fi

# -------------------------
# 2) faillock 설정 값 확인
# -------------------------
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f "$FAILLOCK_CONF" ]; then
  # deny check
  DV="$(strip_comments < "$FAILLOCK_CONF" 2>/dev/null | grep -E '^\s*deny\s*=' | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${DV:-}" ]; then
    DENY_VAL="$DV"
  fi

  # unlock_time check
  UV="$(strip_comments < "$FAILLOCK_CONF" 2>/dev/null | grep -E '^\s*unlock_time\s*=' | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${UV:-}" ]; then
    UNLOCK_TIME_VAL="$UV"
  fi
fi

# PAM 파일 내 인자(argument) 확인 (conf 파일 없을 경우 대비)
if [ -f "$PAM_AUTH" ]; then
  LAST_FL_LINE="$(strip_comments < "$PAM_AUTH" 2>/dev/null | grep -E '\bpam_faillock\.so\b' | tail -n 1 || true)"
  if [ -n "${LAST_FL_LINE:-}" ]; then
    PAM_DENY="$(echo "$LAST_FL_LINE" | grep -oE 'deny=[0-9]+' | tail -n 1 | cut -d= -f2 || true)"
    if [ -n "${PAM_DENY:-}" ] && [ "$DENY_VAL" = "not_set" ]; then
      DENY_VAL="$PAM_DENY"
    fi
    PAM_UNLOCK="$(echo "$LAST_FL_LINE" | grep -oE 'unlock_time=[0-9]+' | tail -n 1 | cut -d= -f2 || true)"
    if [ -n "${PAM_UNLOCK:-}" ] && [ "$UNLOCK_TIME_VAL" = "not_set" ]; then
      UNLOCK_TIME_VAL="$PAM_UNLOCK"
    fi
  fi
fi

# -------------------------
# 3) 판정 (U_03_3 : faillock)
# - 모듈 적용(set)
# - deny >= 1 (임계값 설정됨)
# - unlock_time >= 0 (잠금 정책 존재)
# -------------------------
OK_DENY=0
OK_UNLOCK=0

if [ "$DENY_VAL" != "not_set" ] 2>/dev/null; then
  # deny 값은 숫자여야 하며, 1 이상이어야 함 (0은 잠금 안 함)
  if [[ "$DENY_VAL" =~ ^[0-9]+$ ]] && [ "$DENY_VAL" -ge 1 ]; then
    OK_DENY=1
  fi
fi

if [ "$UNLOCK_TIME_VAL" != "not_set" ] 2>/dev/null; then
  # unlock_time은 숫자여야 함
  if [[ "$UNLOCK_TIME_VAL" =~ ^[0-9]+$ ]] && [ "$UNLOCK_TIME_VAL" -ge 0 ]; then
    OK_UNLOCK=1
  fi
fi

if [ "$FA_LOCK_MODULE" = "set" ] && [ "$OK_DENY" -eq 1 ] && [ "$OK_UNLOCK" -eq 1 ]; then
  FLAG_U_03_3=0 # 양호
else
  FLAG_U_03_3=1 # 취약
fi

# -------------------------
# 4) VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_03_1" -eq 1 ] || [ "$FLAG_U_03_2" -eq 1 ] || [ "$FLAG_U_03_3" -eq 1 ]; then
  IS_VUL=1
fi

# -------------------------
# 5) Output (JSON)
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
      "U_03_1": $FLAG_U_03_1,
      "U_03_2": $FLAG_U_03_2,
      "U_03_3": $FLAG_U_03_3
    },
    "timestamp": "$DATE"
  }
}
EOF