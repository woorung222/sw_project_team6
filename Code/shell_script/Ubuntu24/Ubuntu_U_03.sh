#!/usr/bin/env bash
set -u

# =========================================================
# U_03 (상) 계정 잠금 임계값 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 기준) 로그인 실패 시 계정 잠금(또는 지연/해제시간) 정책 존재 여부 점검
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_03_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_03"
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_03_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
FA_LOCK_MODULE="not_set"     # pam_faillock 적용 여부
DENY_VAL="not_set"           # deny 값
UNLOCK_TIME_VAL="not_set"    # unlock_time 값

# -------------------------
# Helper: 주석 제거한 라인만 대상으로 마지막 설정 우선
# -------------------------
strip_comments() {
  # stdin -> stdout : 주석/공백 라인 제거
  grep -vE '^\s*#' | grep -vE '^\s*$'
}

# -------------------------
# 1) PAM 파일에서 pam_faillock 적용 여부 확인 (Ubuntu/Debian)
# - 보통 /etc/pam.d/common-auth, common-account 쪽에 존재
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
# 2) pam_faillock 설정 값 확인
#   2-1) /etc/security/faillock.conf
#   2-2) PAM 라인 옵션(deny=, unlock_time=)에서 마지막 값
# -------------------------
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f "$FAILLOCK_CONF" ]; then
  # deny
  DV="$(strip_comments < "$FAILLOCK_CONF" 2>/dev/null | grep -E '^\s*deny\s*=' | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${DV:-}" ]; then
    DENY_VAL="$DV"
  fi

  # unlock_time
  UV="$(strip_comments < "$FAILLOCK_CONF" 2>/dev/null | grep -E '^\s*unlock_time\s*=' | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${UV:-}" ]; then
    UNLOCK_TIME_VAL="$UV"
  fi
fi

# PAM 라인에서 deny/unlock_time 옵션을 보조로 파싱 (conf에 없을 때 대비)
# common-auth 내 pam_faillock 라인(들)에서 마지막 옵션 우선
if [ -f "$PAM_AUTH" ]; then
  LAST_FL_LINE="$(strip_comments < "$PAM_AUTH" 2>/dev/null | grep -E '\bpam_faillock\.so\b' | tail -n 1 || true)"
  if [ -n "${LAST_FL_LINE:-}" ]; then
    # deny=
    PAM_DENY="$(echo "$LAST_FL_LINE" | grep -oE 'deny=[0-9]+' | tail -n 1 | cut -d= -f2 || true)"
    if [ -n "${PAM_DENY:-}" ] && [ "$DENY_VAL" = "not_set" ]; then
      DENY_VAL="$PAM_DENY"
    fi
    # unlock_time=
    PAM_UNLOCK="$(echo "$LAST_FL_LINE" | grep -oE 'unlock_time=[0-9]+' | tail -n 1 | cut -d= -f2 || true)"
    if [ -n "${PAM_UNLOCK:-}" ] && [ "$UNLOCK_TIME_VAL" = "not_set" ]; then
      UNLOCK_TIME_VAL="$PAM_UNLOCK"
    fi
  fi
fi

# -------------------------
# 3) 판정 (flag 1개)
# 양호(FLAG=0) 조건(보수적/일반형):
# - pam_faillock 적용(set)
# - deny 값이 숫자이며 1 이상(임계값 존재)
# - unlock_time 값이 숫자이며 0 이상(정책 존재로 간주)
#   * unlock_time은 환경에 따라 "0(관리자 해제)"도 정책으로 볼 수 있어 0 이상 허용
# -------------------------
OK_DENY=0
OK_UNLOCK=0

if [ "$DENY_VAL" != "not_set" ] 2>/dev/null; then
  if [[ "$DENY_VAL" =~ ^[0-9]+$ ]] && [ "$DENY_VAL" -ge 1 ]; then
    OK_DENY=1
  fi
fi

if [ "$UNLOCK_TIME_VAL" != "not_set" ] 2>/dev/null; then
  if [[ "$UNLOCK_TIME_VAL" =~ ^[0-9]+$ ]] && [ "$UNLOCK_TIME_VAL" -ge 0 ]; then
    OK_UNLOCK=1
  fi
fi

if [ "$FA_LOCK_MODULE" = "set" ] && [ "$OK_DENY" -eq 1 ] && [ "$OK_UNLOCK" -eq 1 ]; then
  FLAG_U_03_1=0
else
  FLAG_U_03_1=1
fi

# -------------------------
# 4) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_03_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# 5) Output (JSON: 필요한 필드만)
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
      "U_03_1": $FLAG_U_03_1
    },
    "timestamp": "$DATE"
  }
}
EOF

