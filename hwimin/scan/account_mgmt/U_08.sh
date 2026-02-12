#!/usr/bin/env bash
set -u

# =========================================================
# U_08 (상) /etc/shadow 파일 소유자 및 권한 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) /etc/shadow 소유자 root, 권한 400/600/640 등(기타 권한 0)
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_08_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_08"
CATEGORY="file"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_08_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
SHADOW_OWNER_OK=0
SHADOW_PERM_OK=0

SHADOW_FILE="/etc/shadow"

# -------------------------
# Helper
# -------------------------
stat_val() { stat -c "$1" "$2" 2>/dev/null || true; }

# other 권한이 0인지 확인 (권한 숫자 기준)
other_perm_is_zero() {
  local mode="$1"
  [[ "$mode" =~ ^[0-9]{3,4}$ ]] || return 1
  local o="${mode: -1}"
  [[ "$o" =~ ^[0-9]$ ]] || return 1
  [ "$o" -eq 0 ]
}

# group/other write 포함 여부(권한 숫자 기준) - group은 허용될 수도 있지만, write는 보통 금지
has_write_perm_go() {
  local mode="$1"
  [[ "$mode" =~ ^[0-9]{3,4}$ ]] || return 0
  local go="${mode: -2}"
  local g="${go:0:1}"
  local o="${go:1:1}"
  if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
    return 1
  fi
  return 0
}

# -------------------------
# 1) /etc/shadow 존재/소유자/권한 점검
# -------------------------
if [ -f "$SHADOW_FILE" ]; then
  S_USER="$(stat_val '%U' "$SHADOW_FILE")"
  S_MODE="$(stat_val '%a' "$SHADOW_FILE")"

  # 소유자 root
  if [ "$S_USER" = "root" ]; then
    SHADOW_OWNER_OK=1
  fi

  # 권한:
  # - other(기타) 권한 0 필수
  # - group/other write 금지(보수적)
  if [ -n "${S_MODE:-}" ] && [[ "$S_MODE" =~ ^[0-9]{3,4}$ ]]; then
    if other_perm_is_zero "$S_MODE"; then
      if has_write_perm_go "$S_MODE"; then
        SHADOW_PERM_OK=0
      else
        # 640/600/400 등은 OK, 더 엄격(000 등)은 비정상이라 보수적으로 취약 처리 가능
        SHADOW_PERM_OK=1
      fi
    else
      SHADOW_PERM_OK=0
    fi
  fi
fi

# -------------------------
# 2) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - 소유자 root
# - 권한 적정(other=0 + group/other write 금지)
# -------------------------
if [ "$SHADOW_OWNER_OK" -eq 1 ] && [ "$SHADOW_PERM_OK" -eq 1 ]; then
  FLAG_U_08_1=0
else
  FLAG_U_08_1=1
fi

# -------------------------
# 3) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_08_1" -eq 1 ]; then
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
      "U_08_1": $FLAG_U_08_1
    },
    "timestamp": "$DATE"
  }
}
EOF

