#!/usr/bin/bash 
##### [U-18] /etc/shadow 파일 소유자 및 권한 설정
####### 점검내용: /etc/shadow 파일 권한 적절성 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : /etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_18_1=0


if [ -f /etc/shadow ]; then
		OWNER_NAME=`ls -l /etc/shadow | awk '{print $3}'`
		if [[ $OWNER_NAME =~ root ]]; then
			SHADOW_PERMISSION=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $SHADOW_PERMISSION -le 400 ]; then
				OWNER_PERMISSION=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $OWNER_PERMISSION -eq 0 ] || [ $OWNER_PERMISSION -eq 4 ]; then
					GROUP_PERMISSION=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $GROUP_PERMISSION -eq 0 ]; then
						OTHER_PERMISSION=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $OTHER_PERMISSION -eq 0 ]; then
							#echo "※ U-18 결과 : 양호(Good)" >> $resultfile 2>&1
							U_18_1=0
						else
							#echo "※ U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " /etc/shadow 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							U_18_1=1

							
						fi
					else
						#echo "※ U-18 결과 : N/A" >> $resultfile 2>&1
						#echo " /etc/shadow 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						U_18_1=1
						
					fi
				else
					#echo "※ U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/shadow 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					U_18_1=1
					
				fi
			else
				#echo "※ U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/shadow 파일의 권한이 400보다 큽니다." >> $resultfile 2>&1
				U_18_1=1
				
			fi
		else
			#echo "※ U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/shadow 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			U_18_1=1
			
		fi
	else
		#echo "※ U-18 결과 : N/A" >> $resultfile 2>&1
		#echo " /etc/shadow 파일이 없습니다." >> $resultfile 2>&1
		U_18_1=1
	fi
		IS_VUL=$U_18_1

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-18",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_18_1": $U_18_1,
    },
    "timestamp": "$DATE"
  }
}
EOF