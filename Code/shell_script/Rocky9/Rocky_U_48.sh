#!/bin/bash

# [U-48] expn, vrfy 명령어 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.116-117
# 자동 조치 가능 유무 : 수동 조치 (설정 파일 수정)
# 플래그 설명:
#   U_48_1 : [Sendmail] PrivacyOptions 설정 미흡 (noexpn, novrfy 누락)
#   U_48_2 : [Postfix] disable_vrfy_command 미설정 (취약)
#   U_48_3 : [Exim] vrfy/expn 허용 설정 발견

# --- 점검 로직 시작 ---

# 초기화
U_48_1=0
U_48_2=0
U_48_3=0

# 서비스 활성화 여부 확인 (전체 비활성 시 양호 유지)
if systemctl is-active sendmail >/dev/null 2>&1 || \
   systemctl is-active postfix >/dev/null 2>&1 || \
   systemctl is-active exim >/dev/null 2>&1; then

    # 1. [Sendmail] 점검 (U_48_1)
    if systemctl is-active sendmail >/dev/null 2>&1; then
        CF_FILE="/etc/mail/sendmail.cf"
        if [[ -f "$CF_FILE" ]]; then
            # PrivacyOptions 행 추출 (주석 제외)
            PRIV_OPTS=$(grep -v "^#" "$CF_FILE" 2>/dev/null | grep -i "PrivacyOptions")
            
            # goaway가 있거나, (noexpn AND novrfy)가 있어야 안전
            if [[ "$PRIV_OPTS" == *"goaway"* ]]; then
                U_48_1=0
            elif [[ "$PRIV_OPTS" == *"noexpn"* ]] && [[ "$PRIV_OPTS" == *"novrfy"* ]]; then
                U_48_1=0
            else
                U_48_1=1
            fi
        else
            # 서비스는 켜져있는데 설정 파일이 없으면 점검 불가(취약 간주)
            U_48_1=1
        fi
    fi

    # 2. [Postfix] 점검 (U_48_2)
    if systemctl is-active postfix >/dev/null 2>&1; then
        # disable_vrfy_command 값 확인 (yes여야 함)
        VRFY_CONF=$(postconf -h disable_vrfy_command 2>/dev/null)
        
        if [[ "$VRFY_CONF" != "yes" ]]; then
            U_48_2=1
        fi
    fi

    # 3. [Exim] 점검 (U_48_3)
    if systemctl is-active exim >/dev/null 2>&1; then
        EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
        if [[ -f "$EXIM_CONF" ]]; then
            # acl_smtp_vrfy 또는 acl_smtp_expn에 accept 설정이 있으면 취약
            if grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" | grep -v "^#" | grep -q "accept"; then
                U_48_3=1
            fi
        fi
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_48_1 -eq 1 ]] || [[ $U_48_2 -eq 1 ]] || [[ $U_48_3 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-48",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_48_1": $U_48_1,
      "U_48_2": $U_48_2,
      "U_48_3": $U_48_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
