#!/usr/bin/env bash
set -u

# =========================================================
# U_35 (상) 공유 서비스 익명 접근 제한 | Ubuntu 24.04
# - 진단 기준: FTP/Samba/NFS 등의 익명 접속 허용 여부 및 ftp 계정 존재 여부
# - Rocky 논리 반영:
#   U_35_1 : [FTP] ftp 또는 anonymous 계정 존재 여부
#   U_35_2 : [vsFTP] anonymous_enable=YES 여부
#   U_35_3 : [ProFTP] <Anonymous> 설정 여부
#   U_35_4 : [NFS] anonuid/anongid 옵션 여부
#   U_35_5 : [Samba] guest ok = yes 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_35"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_35_1=0
U_35_2=0
U_35_3=0
U_35_4=0
U_35_5=0

# -------------------------
# 1. [FTP] 계정 점검 (U_35_1)
# -------------------------
# /etc/passwd에 ftp 또는 anonymous 계정이 있는지 확인 (Rocky/Ansible 기준)
if grep -E "^ftp:|^anonymous:" /etc/passwd >/dev/null 2>&1; then
    U_35_1=1
fi

# -------------------------
# 2. [vsFTP] 설정 점검 (U_35_2)
# -------------------------
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTP_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
else
    VSFTP_CONF=""
fi

if [ -n "$VSFTP_CONF" ]; then
    # 주석 제외하고 anonymous_enable=YES 인지 확인
    if grep -v "^#" "$VSFTP_CONF" | grep -i "anonymous_enable" | grep -i "YES" >/dev/null 2>&1; then
        U_35_2=1
    fi
fi

# -------------------------
# 3. [ProFTP] 설정 점검 (U_35_3)
# -------------------------
PRO_CONF="/etc/proftpd/proftpd.conf"
if [ -f "$PRO_CONF" ]; then
    # <Anonymous> 태그가 주석 해제되어 있는지 확인
    if grep -v "^#" "$PRO_CONF" | grep -i "<Anonymous" >/dev/null 2>&1; then
        U_35_3=1
    fi
fi

# -------------------------
# 4. [NFS] 설정 점검 (U_35_4)
# -------------------------
if [ -f "/etc/exports" ]; then
    # anonuid 또는 anongid 옵션이 있는지 확인 (Rocky 기준 통일)
    if grep -v "^#" /etc/exports | grep -Ei "anonuid|anongid" >/dev/null 2>&1; then
        U_35_4=1
    fi
fi

# -------------------------
# 5. [Samba] 설정 점검 (U_35_5)
# -------------------------
if [ -f "/etc/samba/smb.conf" ]; then
    # guest ok = yes 옵션 확인
    if grep -v "^#" /etc/samba/smb.conf 2>/dev/null | grep -i "guest ok" | grep -iw "yes" >/dev/null 2>&1; then
        U_35_5=1
    fi
    # public = yes 옵션 확인 (보조)
    if grep -v "^#" /etc/samba/smb.conf 2>/dev/null | grep -i "public" | grep -iw "yes" >/dev/null 2>&1; then
        U_35_5=1
    fi
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$U_35_1" -eq 1 ] || [ "$U_35_2" -eq 1 ] || [ "$U_35_3" -eq 1 ] || [ "$U_35_4" -eq 1 ] || [ "$U_35_5" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# Output (JSON)
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
      "U_35_1": $U_35_1,
      "U_35_2": $U_35_2,
      "U_35_3": $U_35_3,
      "U_35_4": $U_35_4,
      "U_35_5": $U_35_5
    },
    "timestamp": "$DATE"
  }
}
EOF