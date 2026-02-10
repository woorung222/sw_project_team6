#!/bin/bash

# [U-35] 공유 서비스 익명 접근 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.70-73
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_35_1 : [FTP] 기본 FTP 계정(ftp/anonymous) 존재 발견
#   U_35_2 : [vsFTP] vsftpd 익명 접속 허용 설정 발견
#   U_35_3 : [ProFTP] proftpd 익명 접속 설정 활성화 발견
#   U_35_4 : [NFS] exports 파일 내 익명 접근(anon) 옵션 설정 발견
#   U_35_5 : [Samba] smb.conf 내 익명 사용자 접근(guest ok) 허용 발견

# --- 점검 로직 시작 ---

# 초기화 (0: 양호, 1: 취약)
U_35_1=0
U_35_2=0
U_35_3=0
U_35_4=0
U_35_5=0

# 1. [FTP] 계정 점검 (U_35_1)
if grep -E "^ftp:|^anonymous:" /etc/passwd >/dev/null 2>&1; then
    U_35_1=1
fi

# 2. [vsFTP] 설정 점검 (U_35_2)
VS_CONF="/etc/vsftpd/vsftpd.conf"
[[ ! -f "$VS_CONF" ]] && VS_CONF="/etc/vsftpd.conf"

if [[ -f "$VS_CONF" ]]; then
    # 주석 제외하고 anonymous_enable=YES 여부 확인
    if grep -v "^#" "$VS_CONF" | grep -i "anonymous_enable" | grep -iw "YES" >/dev/null 2>&1; then
        U_35_2=1
    fi
fi

# 3. [ProFTP] 설정 점검 (U_35_3)
PRO_CONF="/etc/proftpd/proftpd.conf"
[[ ! -f "$PRO_CONF" ]] && PRO_CONF="/etc/proftpd.conf"

if [[ -f "$PRO_CONF" ]]; then
    # <Anonymous> 섹션 내 User/UserAlias 설정 여부 확인
    if sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PRO_CONF" 2>/dev/null | grep -vE "^#" | grep -iE "User|UserAlias" >/dev/null 2>&1; then
        U_35_3=1
    fi
fi

# 4. [NFS] 설정 점검 (U_35_4)
if [[ -f "/etc/exports" ]]; then
    # anonuid 또는 anongid 옵션 확인
    if grep -v "^#" /etc/exports | grep -Ei "anonuid|anongid" >/dev/null 2>&1; then
        U_35_4=1
    fi
fi

# 5. [Samba] 설정 점검 (U_35_5)
if [[ -f "/etc/samba/smb.conf" ]]; then
    # guest ok = yes 옵션 확인
    if grep -v "^#" /etc/samba/smb.conf 2>/dev/null | grep -i "guest ok" | grep -iw "yes" >/dev/null 2>&1; then
        U_35_5=1
    fi
fi

# 6. 전체 취약 여부 판단 (하나라도 1이면 1)
IS_VUL=0
if [[ $U_35_1 -eq 1 ]] || [[ $U_35_2 -eq 1 ]] || [[ $U_35_3 -eq 1 ]] || [[ $U_35_4 -eq 1 ]] || [[ $U_35_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 7. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-35",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_35_1": $U_35_1,
      "U_35_2": $U_35_2,
      "U_35_3": $U_35_3,
      "U_35_4": $U_35_4,
      "U_35_5": $U_35_5
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
