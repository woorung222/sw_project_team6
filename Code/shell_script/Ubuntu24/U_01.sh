#!/usr/bin/env bash
set -u

# =========================================================
# U-01 (상) root 계정 원격 접속 제한  | Ubuntu 24.04
# - PDF 판단기준:
#   양호: 원격터미널 미사용 또는(사용 시) root 직접접속 차단
#   취약: 원격터미널 사용 시 root 직접접속 허용
#   (근거: PDF U-01)  :contentReference[oaicite:5]{index=5}
# - 팀 조건:
#   (1) flag=0/flag=1 모두 코드로 판별
#   (2) VULN_STATUS는 flag 집합으로만 산출
# - Rocky 논리:
#   Telnet: pam_securetty + securetty pts 점검
#   SSH   : PermitRootLogin No 점검
#   (단, "서비스 사용 시" 조건을 PDF대로 반영하기 위해 '사용 여부'를 먼저 게이팅)
# =========================================================

ITEM="U_01"
HOST="$(hostname)"
USER="$(whoami)"
IP="$(hostname -I | awk '{print $1}')"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_01"      # '_' 고정
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flags (0: 원인 없음, 1: 원인 존재)
# -------------------------
FLAG_U_01_1=0   # Telnet root 원격 접속 허용(또는 차단 미흡)
FLAG_U_01_2=0   # SSH root 원격 접속 허용(또는 차단 미흡)

# -------------------------
# Evidence (자동화/대시보드용)
# -------------------------
EVID_TELNET_IN_USE="0"
EVID_TELNET_METHOD="none"
EVID_PAM_SECURETTY="not_checked"
EVID_SECURETTY_PTS="not_checked"

EVID_SSH_IN_USE="0"
EVID_SSH_ACTIVE="unknown"
EVID_SSH_LISTEN_22="unknown"
EVID_PERMITROOTLOGIN="not_checked"
EVID_PRL_SOURCE="none"

# -------------------------
# Helpers
# -------------------------
is_listening_tcp() { # $1=port
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ":${1}$"
}

# -------------------------
# 1) Telnet "사용 여부" 판정 (PDF: 서비스 사용 시에만 취약/양호 갈림)
# - Ubuntu 24.04: telnet 기본 비활성인 경우가 많으므로
#   1) 23/tcp LISTEN or 2) systemd telnet.socket 활성 기반으로 판단
# -------------------------
TELNET_IN_USE=0

if is_listening_tcp 23; then
  TELNET_IN_USE=1
  EVID_TELNET_METHOD="port_23_listen"
elif systemctl list-units --type=socket --all 2>/dev/null | grep -qE 'telnet\.socket'; then
  # 존재 자체가 사용 중은 아니므로 active 여부를 한 번 더 확인
  if systemctl is-active --quiet telnet.socket 2>/dev/null; then
    TELNET_IN_USE=1
    EVID_TELNET_METHOD="systemd_telnet_socket_active"
  else
    EVID_TELNET_METHOD="systemd_telnet_socket_inactive"
  fi
else
  EVID_TELNET_METHOD="no_telnet_socket_and_no_port"
fi

EVID_TELNET_IN_USE="$TELNET_IN_USE"

# -------------------------
# 2) U_01_1 (Telnet) flag 판정 (Rocky 논리 기반 + PDF의 '사용 시' 게이팅)
# - 가이드(LINUX Telnet): /etc/pam.d/login에 pam_securetty 적용 + /etc/securetty pts 제거 :contentReference[oaicite:6]{index=6}
# - Ubuntu 20.04+는 securetty가 없을 수 있음(가이드 명시) :contentReference[oaicite:7]{index=7}
# -------------------------
if [ "$TELNET_IN_USE" -eq 1 ]; then
  PAM_LOGIN="/etc/pam.d/login"
  SECURETTY="/etc/securetty"

  # (A) pam_securetty.so 존재(주석 제외)
  if [ -f "$PAM_LOGIN" ]; then
    if grep -v '^\s*#' "$PAM_LOGIN" 2>/dev/null | grep -qE 'pam_securetty\.so'; then
      EVID_PAM_SECURETTY="set"
    else
      EVID_PAM_SECURETTY="not_set"
      FLAG_U_01_1=1
    fi
  else
    EVID_PAM_SECURETTY="file_missing"
    FLAG_U_01_1=1
  fi

  # (B) securetty의 pts 존재 여부 (파일이 있을 때만 검사)
  if [ -f "$SECURETTY" ]; then
    if grep -v '^\s*#' "$SECURETTY" 2>/dev/null | grep -qE '^\s*pts/'; then
      EVID_SECURETTY_PTS="pts_present"
      FLAG_U_01_1=1
    else
      EVID_SECURETTY_PTS="pts_not_present"
    fi
  else
    # Ubuntu 20.04+에서 securetty가 없는 경우가 있음(가이드에 언급) :contentReference[oaicite:8]{index=8}
    EVID_SECURETTY_PTS="file_missing"
    # securetty가 없다는 이유만으로 취약(=1)로 만들지는 않음.
    # Telnet 사용 중이면 핵심은 pam_securetty 적용 여부로 충분히 판정 가능하도록 설계.
  fi
else
  # Telnet 미사용이면 PDF 기준 양호 방향 (flag=0)
  EVID_PAM_SECURETTY="not_applicable"
  EVID_SECURETTY_PTS="not_applicable"
  FLAG_U_01_1=0
fi

# -------------------------
# 3) SSH "사용 여부" 판정 (active + 22/tcp LISTEN)
# -------------------------
SSH_ACTIVE=0
SSH_LISTEN_22=0

systemctl is-active --quiet ssh 2>/dev/null && SSH_ACTIVE=1
is_listening_tcp 22 && SSH_LISTEN_22=1

EVID_SSH_ACTIVE="$SSH_ACTIVE"
EVID_SSH_LISTEN_22="$SSH_LISTEN_22"

SSH_IN_USE=0
if [ "$SSH_ACTIVE" -eq 1 ] && [ "$SSH_LISTEN_22" -eq 1 ]; then
  SSH_IN_USE=1
fi
EVID_SSH_IN_USE="$SSH_IN_USE"

# -------------------------
# 4) U_01_2 (SSH) flag 판정 (Rocky 논리 기반 + PDF)
# - 가이드: PermitRootLogin No :contentReference[oaicite:9]{index=9}
# - SSH 사용 중인데 PermitRootLogin이 "no"가 아니거나, 아예 명시되지 않으면 flag=1
# -------------------------
if [ "$SSH_IN_USE" -eq 1 ]; then
  # Ubuntu는 drop-in(/etc/ssh/sshd_config.d)도 있으므로 둘 다 확인하되,
  # "마지막으로 발견된 값"을 우선으로 사용(후순위 파일이 override될 수 있음)
  PRL_LINE="$(grep -RhisE '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | tail -n 1 || true)"
  if [ -n "$PRL_LINE" ]; then
    PRL_VALUE="$(echo "$PRL_LINE" | awk '{print $2}')"
    EVID_PERMITROOTLOGIN="${PRL_VALUE}"
    EVID_PRL_SOURCE="config_or_dropin"
    if [ "${PRL_VALUE,,}" = "no" ]; then
      FLAG_U_01_2=0
    else
      FLAG_U_01_2=1
    fi
  else
    EVID_PERMITROOTLOGIN="not_set"
    EVID_PRL_SOURCE="not_found"
    FLAG_U_01_2=1
  fi
else
  EVID_PERMITROOTLOGIN="not_applicable"
  EVID_PRL_SOURCE="not_applicable"
  FLAG_U_01_2=0
fi

# -------------------------
# 5) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_01_1" -eq 1 ] || [ "$FLAG_U_01_2" -eq 1 ]; then
  VULN_STATUS="VULNERABLE"
else
  VULN_STATUS="SAFE"
fi

# -------------------------
# 6) Output (JSON: 필요한 필드만)
# -------------------------

# is_vul: flag OR
IS_VUL=0
[ "$FLAG_U_01_1" -eq 1 ] || [ "$FLAG_U_01_2" -eq 1 ] && IS_VUL=1

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
      "U_01_1": $FLAG_U_01_1,
      "U_01_2": $FLAG_U_01_2
    },
    "timestamp": "$DATE"
  }
}
EOF

