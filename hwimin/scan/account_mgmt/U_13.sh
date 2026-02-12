#!/usr/bin/env bash
set -u

# =========================================================
# U_13 (상) SUID/SGID 설정 파일 점검 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) 불필요하거나 과도한 SUID/SGID 파일 존재 여부 점검
# - 자동화 한계: "불필요" 판단은 환경별 상이 → 기본은 '탐지 시 취약'으로 보수 처리
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_13_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_13"
CATEGORY="file"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_13_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
FOUND_SUID_SGID=0

# -------------------------
# Helper: 제외 경로(가상/임시/컨테이너/런타임)
# -------------------------
PRUNE_PATHS=(
  "/proc"
  "/sys"
  "/run"
  "/dev"
  "/snap"
  "/var/lib/docker"
  "/var/lib/containerd"
)

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
# 1) SUID/SGID 파일 탐색
# - -perm -4000 : SUID
# - -perm -2000 : SGID
# - 하나라도 있으면 기본적으로 "존재"로 판정
#   (PDF는 보통 '불필요한 SUID/SGID 제거'를 요구하므로 자동진단은 보수적으로 처리)
# -------------------------
PRUNE_EXPR="$(build_prune_expr)"

# 첫 발견 즉시 종료(-quit), 에러 무시
if eval "find / $PRUNE_EXPR -o -type f \\( -perm -4000 -o -perm -2000 \\) -print -quit" 2>/dev/null | grep -q '.'; then
  FOUND_SUID_SGID=1
fi

# -------------------------
# 2) 판정 (flag 1개)
# 양호(FLAG=0) 조건(보수적 자동진단):
# - SUID/SGID 파일이 '전혀' 없으면 양호
# 취약(FLAG=1):
# - 하나라도 발견되면 취약
# -------------------------
if [ "$FOUND_SUID_SGID" -eq 0 ]; then
  FLAG_U_13_1=0
else
  FLAG_U_13_1=1
fi

# -------------------------
# 3) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_13_1" -eq 1 ]; then
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
      "U_13_1": $FLAG_U_13_1
    },
    "timestamp": "$DATE"
  }
}
EOF

