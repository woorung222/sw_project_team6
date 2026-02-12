#!/usr/bin/env bash
set -u

# =========================================================
# U_07 (상) /etc/passwd 파일 소유자 및 권한 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) /etc/passwd 소유자 root, 권한 644 이하(그룹/기타 쓰기 금지)
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_07_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_07"
CATEGORY="file"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_07_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
PASSWD_OWNER_OK=0
PASSWD_PERM_OK=0

PASSWD_FILE="/etc/passwd"

# -------------------------
# Helper
# -------------------------
stat_val() { stat -c "$1" "$2" 2>/dev/null || true; }

# group/other write 포함 여부(권한 숫자 기준)
has_write_perm_go() {
  # input: mode (예: 644, 664, 600, 775)
  local mode="$1"
  [[ "$mode" =~ ^[0-9]{3,4}$ ]] || return 0
  local go="${mode: -2}"
  local g="${go:0:1}"
  local o="${go:1:1}"
  # 2,3,6,7이면 write 포함
  if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
    return 1
  fi
  return 0
}

# -------------------------
# 1) /etc/passwd 존재/소유자/권한 점검
# -------------------------
if [ -f "$PASSWD_FILE" ]; then
  P_USER="$(stat_val '%U' "$PASSWD_FILE")"
  P_MODE="$(stat_val '%a' "$PASSWD_FILE")"

  # 소유자 root
  if [ "$P_USER" = "root" ]; then
    PASSWD_OWNER_OK=1
  fi

  # 권한: group/other write 금지 + 644 이하를 권장치로 수용
  if [ -n "${P_MODE:-}" ] && [[ "$P_MODE" =~ ^[0-9]{3,4}$ ]]; then
    if has_write_perm_go "$P_MODE"; then
      PASSWD_PERM_OK=0
    else
      # 추가로 644 이하 권장(더 엄격한 600/640 등도 포함)
      if [ "$P_MODE" -le 644 ]; then
        PASSWD_PERM_OK=1
      else
        # 예: 655 같은 비표준 권한은 보수적으로 취약
        PASSWD_PERM_OK=0
      fi
    fi
  fi
fi

# -------------------------
# 2) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - 소유자 root
# - 권한 적정(그룹/기타 쓰기 금지 + 644 이하)
# -------------------------
if [ "$PASSWD_OWNER_OK" -eq 1 ] && [ "$PASSWD_PERM_OK" -eq 1 ]; then
  FLAG_U_07_1=0
else
  FLAG_U_07_1=1
fi

# -------------------------
# 3) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_07_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# 4) Output (JSON: 필요한 필드만)
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
      "U_07_1": $FLAG_U_07_1
    },
    "timestamp": "$DATE"
  }
}
EOF

