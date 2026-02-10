#!/usr/bin/bash 
##### [U-15]파일 및 디렉터리 소유자 설정
####### 점검내용: 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_15_1=0

if [ `find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l` -gt 0 ]; then
	##echo "※ U-15 결과 : 취약(Vulnerable)"  > $resultfile 2>&1
	#echo " 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다."  > $resultfile 2>&1
  U_15_1=1
else
	#echo "※ U-15 결과 : 양호(Good)"  > $resultfile 2>&1
  U_15_1=0
fi
	IS_VUL=$U_15_1

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-15",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_15_1": $U_15_1,
    },
    "timestamp": "$DATE"
  }
}
EOF