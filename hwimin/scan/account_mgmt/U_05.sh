#!/usr/bin/env bash
set -u

# =========================================================
# U_05 (상) root홈/패스 디렉터리 권한 및 PATH 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) root PATH에 "." 포함 금지, PATH 디렉터리의 소유자/권한 적정
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_05_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_05"
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_05_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
PATH_SAFE=0
PATH_DIRS_SAFE=0
ROOT_HOME_SAFE=0

# -------------------------
# Helper
# -------------------------
stat_val() { stat -c "$1" "$2" 2>/dev/null || true; }

has_write_perm_go() {
  # group/other에 write가 있으면 1(취약), 아니면 0
  # input: mode(예: 755)
  local mode="$1"
  [[ "$mode" =~ ^[0-9]{3,4}$ ]] || return 0
  local go="${mode: -2}"   # 마지막 두 자리 (group, other)
  local g="${go:0:1}"
  local o="${go:1:1}"
  # 2,3,6,7 이면 write 포함
  if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
    return 1
  fi
  return 0
}

# =========================================================
# 0) root 권한 권장: root PATH/권한 검사가 핵심이므로
# =========================================================
if [ "$(id -u)" -ne 0 ]; then
  # root로 실행되지 않으면 보수적으로 취약 유지 (검증 불가)
  FLAG_U_05_1=1
else
  # =======================================================
  # 1) root HOME 권한 점검
  # - 소유자 root, group/other write 금지
  # =======================================================
  ROOT_HOME="$(getent passwd root | awk -F: '{print $6}')"
  if [ -n "${ROOT_HOME:-}" ] && [ -d "$ROOT_HOME" ]; then
    RH_USER="$(stat_val '%U' "$ROOT_HOME")"
    RH_MODE="$(stat_val '%a' "$ROOT_HOME")"
    if [ "$RH_USER" = "root" ] && [ -n "${RH_MODE:-}" ]; then
      if has_write_perm_go "$RH_MODE"; then
        ROOT_HOME_SAFE=0
      else
        ROOT_HOME_SAFE=1
      fi
    fi
  fi

  # =======================================================
  # 2) PATH 문자열 자체 안전성 점검
  # - "." 포함 금지
  # - 빈 항목(::), 선행/후행 콜론(:) 금지 (빈 항목은 현재 디렉토리 의미)
  # =======================================================
  ROOT_PATH="${PATH:-}"

  BAD_PATH=0
  # 빈 항목(선행/후행 ":" 또는 "::") → 취약
  if [[ "$ROOT_PATH" == :* ]] || [[ "$ROOT_PATH" == *: ]] || [[ "$ROOT_PATH" == *::* ]]; then
    BAD_PATH=1
  fi
  # "." 항목 포함 → 취약 (정확히 항목 단위로 검사)
  # 케이스: ".:", ":.", ":.:" 등
  if echo "$ROOT_PATH" | awk -F: '{for(i=1;i<=NF;i++){if($i=="."){exit 0}} exit 1}'; then
    BAD_PATH=1
  fi

  if [ "$BAD_PATH" -eq 0 ] && [ -n "${ROOT_PATH:-}" ]; then
    PATH_SAFE=1
  else
    PATH_SAFE=0
  fi

  # =======================================================
  # 3) PATH 디렉터리 권한 점검
  # - 각 디렉터리: 존재해야 함
  # - 소유자 root
  # - group/other write 금지
  # =======================================================
  DIR_OK=1
  IFS=':' read -r -a PATH_ARR <<< "$ROOT_PATH"
  for d in "${PATH_ARR[@]}"; do
    # 빈 항목/공백은 이미 BAD_PATH에서 걸러졌지만 방어적으로 처리
    if [ -z "${d:-}" ]; then
      DIR_OK=0
      break
    fi
    # 상대경로는 보수적으로 취약 처리(권장: 절대경로)
    if [[ "$d" != /* ]]; then
      DIR_OK=0
      break
    fi
    if [ ! -d "$d" ]; then
      DIR_OK=0
      break
    fi
    D_USER="$(stat_val '%U' "$d")"
    D_MODE="$(stat_val '%a' "$d")"
    if [ "$D_USER" != "root" ] || [ -z "${D_MODE:-}" ]; then
      DIR_OK=0
      break
    fi
    if has_write_perm_go "$D_MODE"; then
      DIR_OK=0
      break
    fi
  done

  if [ "$DIR_OK" -eq 1 ]; then
    PATH_DIRS_SAFE=1
  else
    PATH_DIRS_SAFE=0
  fi

  # =======================================================
  # 4) 판정 (flag 1개)
  # 양호(FLAG=0) 조건(보수적/일반형):
  # - root HOME: group/other write 금지 + 소유자 root
  # - PATH 문자열: "."/빈항목 없음
  # - PATH 디렉터리: 소유자 root + group/other write 금지 + 절대경로 + 존재
  # =======================================================
  if [ "$ROOT_HOME_SAFE" -eq 1 ] && [ "$PATH_SAFE" -eq 1 ] && [ "$PATH_DIRS_SAFE" -eq 1 ]; then
    FLAG_U_05_1=0
  else
    FLAG_U_05_1=1
  fi
fi

# -------------------------
# VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_05_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# Output (JSON: 필요한 필드만)
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
      "U_05_1": $FLAG_U_05_1
    },
    "timestamp": "$DATE"
  }
}
EOF
