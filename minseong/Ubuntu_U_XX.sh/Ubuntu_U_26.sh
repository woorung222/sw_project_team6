#!/usr/bin/bash 
##### [U-26] /dev에 존재하지 않는 device 파일 점검
####### 점검내용: 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : /dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_26_1=0


if [ `find /dev -type f 2>/dev/null | wc -l` -gt 0 ]; then
		#echo "※ U-26 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " /dev 디렉터리에 존재하지 않는 device 파일이 존재합니다." >> $resultfile 2>&1
		 U_26_1=1
else
		#echo "※ U-26 결과 : 양호(Good)" >> $resultfile 2>&1
		 U_26_1=0
fi
IS_VUL=$U_26_1
		 cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-26",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_26_1": $U_26_1,
    },
    "timestamp": "$DATE"
  }
}
EOF