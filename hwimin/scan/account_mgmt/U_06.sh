#!/usr/bin/env bash
set -u

# =========================================================
# U_06 (상) 파일 및 디렉터리 소유자 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) 소유자 없는 파일/디렉터리(UID 미존재) 및
#   소유 그룹 없는 파일/디렉터리(GID 미존재) 존재 여부 점검
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_06_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_06"
CATEGORY="file"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_06_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
HAS_NOUSER=0
HAS_NOGROUP=0

# -------------------------
# Helper: 제외 경로(가상/임시/컨테이너/런타임)
# - 스캔 안정성/시간을 위해 PDF 실무 관행대로 제외
# -------------------------
PRUNE_PATHS=(
  "/proc"
  "/sys"
  "/run"
  "/dev"
  "/snap"
  "/var/lib/docker"
  "/var/lib/containerd"
  "/var/lib/snapd"
)

# find prune 표현 생성
build_prune_expr() {
  local first=1
  for p in "${PRUNE_PATHS[@]}"; do
    if [ "$first" -eq 1 ]; then
      printf " -path %q -prune " "$p"
      first=0
    else
      printf " -o -path %q -prune " "$p"
    fi
  done
}

# -------------------------
# 1) 소유자/소유그룹 없는 파일 탐색
# - -nouser / -nogroup
# - 존재하면 취약
# -------------------------
# 성능: 첫 발견 즉시 종료(-quit) / 에러는 무시
PRUNE_EXPR="$(build_prune_expr)"

# -nouser 검사
if eval "find / $PRUNE_EXPR -o -type f -nouser -print -quit" 2>/dev/null | grep -q '.'; then
  HAS_NOUSER=1
fi
# 디렉터리도 포함하고 싶으면 -type f 제거가 더 포괄적이지만, 보수적으로 파일/디렉터리 둘 다 보려면 -type f 삭제 가능.
# 여기서는 PDF 관행대로 파일 중심으로 보되, 디렉터리도 포함시키기 위해 -type f 대신 -type f -o -type d 를 사용
if [ "$HAS_NOUSER" -eq 0 ]; then
  if eval "find / $PRUNE_EXPR -o \\( -type f -o -type d \\) -nouser -print -quit" 2>/dev/null | grep -q '.'; then
    HAS_NOUSER=1
  fi
fi

# -nogroup 검사
if eval "find / $PRUNE_EXPR -o \\( -type f -o -type d \\) -nogroup -print -quit" 2>/dev/null | grep -q '.'; then
  HAS_NOGROUP=1
fi

# -------------------------
# 2) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - nouser 없음
# - nogroup 없음
# -------------------------
if [ "$HAS_NOUSER" -eq 0 ] && [ "$HAS_NOGROUP" -eq 0 ]; then
  FLAG_U_06_1=0
else
  FLAG_U_06_1=1
fi

# -------------------------
# 3) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_06_1" -eq 1 ]; then
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
      "U_06_1": $FLAG_U_06_1
    },
    "timestamp": "$DATE"
  }
}
EOF
