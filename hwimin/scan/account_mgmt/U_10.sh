#!/usr/bin/env bash
set -u

# =========================================================
# U_10 (상) /etc/(x)inetd.conf 및 inetd 서비스 파일 권한 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) inetd/xinetd 설정파일 및 서비스 설정파일 소유자/권한 적정
# - Ubuntu 24.04: xinetd/inetd 미설치인 경우가 흔함 → "없으면 양호"로 판정(설정파일 영향 없음)
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_10_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_10"
CATEGORY="file"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_10_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
ALL_OK=1

# -------------------------
# Helper
# -------------------------
stat_val() { stat -c "$1" "$2" 2>/dev/null || true; }

# group/other write 포함 여부(권한 숫자 기준)
has_write_perm_go() {
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

check_file_owner_perm() {
  # $1: file path
  # return: 0=OK, 1=NOT OK
  local f="$1"
  local u m
  [ -f "$f" ] || return 0  # 없으면 검사대상 아님(OK)
  u="$(stat_val '%U' "$f")"
  m="$(stat_val '%a' "$f")"

  # 소유자 root 필수
  [ "$u" = "root" ] || return 1

  # 권한: group/other write 금지 + 644 이하 권장(더 엄격 OK)
  if [ -z "${m:-}" ] || ! [[ "$m" =~ ^[0-9]{3,4}$ ]]; then
    return 1
  fi
  if has_write_perm_go "$m"; then
    return 1
  fi
  [ "$m" -le 644 ] || return 1

  return 0
}

# -------------------------
# 1) 대상 파일/디렉터리 정의
# -------------------------
TARGETS=(
  "/etc/inetd.conf"
  "/etc/xinetd.conf"
)

# xinetd 서비스 설정 디렉터리(있으면 내부 파일까지 점검)
XINETD_DIR="/etc/xinetd.d"

# -------------------------
# 2) inetd/xinetd 자체 설치 여부에 따른 처리
# - Ubuntu 24.04는 보통 미설치: 관련 파일이 없으면 양호 판단이 합리적
# - 단, 파일이 존재하면 권한/소유자 반드시 점검
# -------------------------
for f in "${TARGETS[@]}"; do
  if ! check_file_owner_perm "$f"; then
    ALL_OK=0
  fi
done

if [ -d "$XINETD_DIR" ]; then
  # 디렉터리 자체 권한도 보수적으로 점검(소유자 root, group/other write 금지)
  XU="$(stat_val '%U' "$XINETD_DIR")"
  XM="$(stat_val '%a' "$XINETD_DIR")"
  if [ "$XU" != "root" ] || [ -z "${XM:-}" ] || ! [[ "$XM" =~ ^[0-9]{3,4}$ ]]; then
    ALL_OK=0
  else
    if has_write_perm_go "$XM"; then
      ALL_OK=0
    fi
  fi

  # 내부 파일 점검: 하나라도 위반이면 취약
  while IFS= read -r -d '' ff; do
    if ! check_file_owner_perm "$ff"; then
      ALL_OK=0
      break
    fi
  done < <(find "$XINETD_DIR" -maxdepth 1 -type f -print0 2>/dev/null || true)
fi

# -------------------------
# 3) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - 관련 파일/디렉터리가 존재하면 소유자/권한 적정
# - 관련 구성 자체가 없다면(미사용) 양호
# -------------------------
if [ "$ALL_OK" -eq 1 ]; then
  FLAG_U_10_1=0
else
  FLAG_U_10_1=1
fi

# -------------------------
# 4) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_10_1" -eq 1 ]; then
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
      "U_10_1": $FLAG_U_10_1
    },
    "timestamp": "$DATE"
  }
}
EOF

