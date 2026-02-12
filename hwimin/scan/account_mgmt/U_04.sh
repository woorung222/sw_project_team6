#!/usr/bin/env bash
set -u

# =========================================================
# U_04 (상) 패스워드 파일 보호 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) /etc/passwd, /etc/shadow 접근권한/소유자 적정성 + 빈 비밀번호 계정 점검
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_04_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_04"
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_04_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
PASSWD_OK=0
SHADOW_OK=0
NO_EMPTY_PW=0

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"

# -------------------------
# Helper: stat 값 읽기 (실패 시 빈 문자열)
# -------------------------
stat_val() {
  # $1: format, $2: file
  stat -c "$1" "$2" 2>/dev/null || true
}

# -------------------------
# 1) /etc/passwd 권한/소유자 점검
# - 일반 권장: 소유자 root, 권한 644 이하(더 엄격하면 OK)
# -------------------------
if [ -f "$PASSWD_FILE" ]; then
  PASSWD_MODE="$(stat_val '%a' "$PASSWD_FILE")"
  PASSWD_USER="$(stat_val '%U' "$PASSWD_FILE")"
  PASSWD_GROUP="$(stat_val '%G' "$PASSWD_FILE")"

  # 권한: 644 이하(숫자 비교 위해 정수로 취급)
  # - 600/640/644 등은 OK, 664/666 등 그룹/기타 쓰기면 취약
  if [[ "${PASSWD_MODE:-}" =~ ^[0-9]+$ ]] && [ "$PASSWD_USER" = "root" ]; then
    # 그룹은 환경마다 root/root가 흔하지만, PDF에서 보통 소유자 root가 핵심
    if [ "$PASSWD_MODE" -le 644 ]; then
      PASSWD_OK=1
    fi
  fi
fi

# -------------------------
# 2) /etc/shadow 권한/소유자 점검
# - 일반 권장: 소유자 root, 권한 400/600/640 등(others=0)
# - 핵심: "기타 사용자(other)" 읽기/쓰기/실행 권한이 없어야 함
# -------------------------
if [ -f "$SHADOW_FILE" ]; then
  SHADOW_MODE="$(stat_val '%a' "$SHADOW_FILE")"
  SHADOW_USER="$(stat_val '%U' "$SHADOW_FILE")"
  SHADOW_GROUP="$(stat_val '%G' "$SHADOW_FILE")"

  if [[ "${SHADOW_MODE:-}" =~ ^[0-9]+$ ]] && [ "$SHADOW_USER" = "root" ]; then
    # other 권한(마지막 자리)이 0이면 OK (예: 640, 600, 400)
    OTHER_PERM="${SHADOW_MODE: -1}"
    if [[ "${OTHER_PERM:-}" =~ ^[0-9]$ ]] && [ "$OTHER_PERM" -eq 0 ]; then
      SHADOW_OK=1
    fi
  fi
fi

# -------------------------
# 3) 빈 비밀번호 계정 점검
# - /etc/shadow의 2번째 필드가 빈 값이면 빈 비밀번호로 간주(취약)
# - /etc/shadow 읽기 권한이 없으면 보수적으로 취약 처리
# -------------------------
if [ -r "$SHADOW_FILE" ]; then
  if awk -F: '($2==""){print $1}' "$SHADOW_FILE" 2>/dev/null | grep -q '.'; then
    NO_EMPTY_PW=0
  else
    NO_EMPTY_PW=1
  fi
else
  NO_EMPTY_PW=0
fi

# -------------------------
# 4) 판정 (flag 1개)
# 양호(FLAG=0) 조건(보수적/일반형):
# - /etc/passwd 권한/소유자 적정
# - /etc/shadow 권한/소유자 적정
# - 빈 비밀번호 계정 없음
# -------------------------
if [ "$PASSWD_OK" -eq 1 ] && [ "$SHADOW_OK" -eq 1 ] && [ "$NO_EMPTY_PW" -eq 1 ]; then
  FLAG_U_04_1=0
else
  FLAG_U_04_1=1
fi

# -------------------------
# 5) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_04_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# 6) Output (JSON: 필요한 필드만)
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
      "U_04_1": $FLAG_U_04_1
    },
    "timestamp": "$DATE"
  }
}
EOF

