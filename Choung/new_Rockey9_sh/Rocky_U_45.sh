#!/bin/bash

# [U-45] 메일 서비스 버전 점검
# 대상 운영체제 : Rocky Linux 9
# 자동 조치 가능 유무 : 가능 (dnf update)
# 플래그 설명:
#   U_45_1 : Sendmail 존재 (경고)
#   U_45_2 : Sendmail 버전 미흡 (취약)
#   U_45_3 : Postfix 존재 (경고)
#   U_45_4 : Postfix 버전 미흡 (취약)
#   U_45_5 : Exim 존재 (경고)
#   U_45_6 : Exim 버전 미흡 (취약)

# --- 점검 로직 시작 ---

# 초기화
U_45_1=0 # Sendmail 존재
U_45_2=0 # Sendmail 버전
U_45_3=0 # Postfix 존재
U_45_4=0 # Postfix 버전
U_45_5=0 # Exim 존재
U_45_6=0 # Exim 버전

# 1. Sendmail 점검
# 존재 여부 확인 (패키지 설치 OR 프로세스 실행)
DETECTED_SENDMAIL=0
if rpm -q sendmail >/dev/null 2>&1; then
    DETECTED_SENDMAIL=1
elif ps -e -o comm | grep -v "grep" | grep -xw "sendmail" >/dev/null 2>&1; then
    DETECTED_SENDMAIL=1
fi

if [[ $DETECTED_SENDMAIL -eq 1 ]]; then
    U_45_1=1
    # 버전 최신 여부 확인 (업데이트 가능 목록에 뜨면 취약)
    # dnf check-update의 exit code: 100(업데이트 있음), 0(없음), 1(에러)
    if dnf check-update "sendmail" -q >/dev/null 2>&1; then
        # exit code가 0이 아니거나 출력이 있으면 업데이트 필요
        # 명확하게 하기 위해 출력 문자열 체크
        if dnf check-update "sendmail" -q | grep -w "sendmail" >/dev/null 2>&1; then
            U_45_2=1
        fi
    fi
fi

# 2. Postfix 점검
DETECTED_POSTFIX=0
if rpm -q postfix >/dev/null 2>&1; then
    DETECTED_POSTFIX=1
elif ps -e -o comm | grep -v "grep" | grep -xw "postfix" >/dev/null 2>&1; then
    DETECTED_POSTFIX=1
fi

if [[ $DETECTED_POSTFIX -eq 1 ]]; then
    U_45_3=1
    if dnf check-update "postfix" -q | grep -w "postfix" >/dev/null 2>&1; then
        U_45_4=1
    fi
fi

# 3. Exim 점검
DETECTED_EXIM=0
if rpm -q exim >/dev/null 2>&1; then
    DETECTED_EXIM=1
elif ps -e -o comm | grep -v "grep" | grep -xw "exim" >/dev/null 2>&1; then
    DETECTED_EXIM=1
fi

if [[ $DETECTED_EXIM -eq 1 ]]; then
    U_45_5=1
    if dnf check-update "exim" -q | grep -w "exim" >/dev/null 2>&1; then
        U_45_6=1
    fi
fi

# 4. 전체 취약 여부 판단
# 단순 설치(홀수 플래그)는 경고이므로 제외하고, 버전 미흡(짝수 플래그)일 때만 취약 판정
IS_VUL=0
if [[ $U_45_2 -eq 1 ]] || [[ $U_45_4 -eq 1 ]] || [[ $U_45_6 -eq 1 ]]; then
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
    "flag_id": "U-45",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_45_1": $U_45_1,
      "U_45_2": $U_45_2,
      "U_45_3": $U_45_3,
      "U_45_4": $U_45_4,
      "U_45_5": $U_45_5,
      "U_45_6": $U_45_6
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
