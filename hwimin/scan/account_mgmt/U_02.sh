#!/usr/bin/env bash
set -u

# =========================================================
# U_02 (상) 비밀번호 관리정책 설정 | Ubuntu 24.04 (Debian 계열)
# - 팀 조건: flag 0/1 모두 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_02_1)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_02"          # '_' 고정
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_02_1=1  # 기본은 보수적으로 취약(증거로 양호를 입증하면 0)

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
PAM_PWQUALITY="not_set"
MINLEN="not_set"
CREDITS="not_set"
ENFORCE_FOR_ROOT="not_set"

# -------------------------
# 1) PAM 적용 여부 점검 (Debian/Ubuntu)
# - /etc/pam.d/common-password 에 pwquality 모듈 적용 확인
# -------------------------
PAM_FILE="/etc/pam.d/common-password"
if [ -f "$PAM_FILE" ]; then
  if grep -v '^\s*#' "$PAM_FILE" 2>/dev/null | grep -qE '\bpam_pwquality\.so\b|\bpam_pwquality\b'; then
    PAM_PWQUALITY="set"
  fi
fi

# -------------------------
# 2) pwquality 설정 점검
# - /etc/security/pwquality.conf 에서 minlen/credit류/enforce_for_root 확인
# -------------------------
CONF="/etc/security/pwquality.conf"
if [ -f "$CONF" ]; then
  # minlen
  ML="$(grep -E '^\s*minlen\s*=' "$CONF" 2>/dev/null | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ -n "${ML:-}" ]; then
    MINLEN="$ML"
  fi

  # credits (dcredit/ucredit/lcredit/ocredit) 또는 minclass 중 하나라도 있으면 복잡도 설정 "존재"로 간주
  if grep -Eq '^\s*(dcredit|ucredit|lcredit|ocredit|minclass)\s*=' "$CONF" 2>/dev/null; then
    CREDITS="set"
  fi

  # enforce_for_root
  if grep -Eq '^\s*enforce_for_root\s*' "$CONF" 2>/dev/null; then
    ENFORCE_FOR_ROOT="set"
  fi
fi

# -------------------------
# 3) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - PAM pwquality 적용(set)
# - minlen >= 8 확인
# - 복잡도 설정 존재(set)
# -------------------------
OK_MINLEN=0
if [ "$MINLEN" != "not_set" ] 2>/dev/null; then
  # 숫자 비교 가능한 경우만
  if [[ "$MINLEN" =~ ^[0-9]+$ ]] && [ "$MINLEN" -ge 8 ]; then
    OK_MINLEN=1
  fi
fi

if [ "$PAM_PWQUALITY" = "set" ] && [ "$OK_MINLEN" -eq 1 ] && [ "$CREDITS" = "set" ]; then
  FLAG_U_02_1=0
else
  FLAG_U_02_1=1
fi

# -------------------------
# 4) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_02_1" -eq 1 ]; then
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
      "U_02_1": $FLAG_U_02_1
    },
    "timestamp": "$DATE"
  }
}
EOF

