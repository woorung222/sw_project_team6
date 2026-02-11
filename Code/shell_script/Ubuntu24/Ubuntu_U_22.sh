#!/usr/bin/bash 
##### [U-22] /etc/services 파일 소유자 및 권한 설정
####### 점검내용: /etc/services 파일 권한 적절성 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 

####### [취약 조건] : /etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_22_1=0



if [ -f /etc/services ]; then
		etc_services_owner_name=`ls -l /etc/services | awk '{print $3}'`
		if [[ $etc_services_owner_name =~ root ]] || [[ $etc_services_owner_name =~ bin ]] || [[ $etc_services_owner_name =~ sys ]]; then
			etc_services_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_services_permission -le 644 ]; then
				etc_services_owner_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_services_owner_permission -eq 6 ] || [ $etc_services_owner_permission -eq 4 ] || [ $etc_services_owner_permission -eq 2 ] || [ $etc_services_owner_permission -eq 0 ]; then
					etc_services_group_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_services_group_permission -eq 4 ] || [ $etc_services_group_permission -eq 0 ]; then
						etc_services_other_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_services_other_permission -eq 4 ] || [ $etc_services_other_permission -eq 0 ]; then
							#echo "※ U-22 결과 : 양호(Good)" >> $resultfile 2>&1
							U_22_1=0
						else
							#echo "※ U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " /etc/services 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							 U_22_1=1
						fi
					else
						#echo "※ U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/services 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						 U_22_1=1
					fi
				else
					#echo "※ U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/services 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					 U_22_1=1
				fi
			else
				#echo "※ U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/services 파일의 권한이 644보다 큽니다." >> $resultfile 2>&1
				 U_22_1=1
			fi
		else
			#echo "※ U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/services 파일의 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다." >> $resultfile 2>&1
			 U_22_1=1
		fi
	else
		#echo "※ U-22 결과 : N/A" >> $resultfile 2>&1
		#echo " /etc/services 파일이 없습니다." >> $resultfile 2>&1
		 U_22_1=0
	fi
	IS_VUL=$U_22_1
		cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-22",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_22_1": $U_22_1,
    },
    "timestamp": "$DATE"
  }
}
EOF