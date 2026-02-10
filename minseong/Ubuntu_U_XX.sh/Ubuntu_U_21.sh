#!/usr/bin/bash 
##### [U-21] /etc/(r)syslog.conf 파일 소유자 및 권한 설정
####### 점검내용: /etc/(r)syslog.conf 파일 권한 적절성 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] :/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_21_1=0

syslogconf_files=("/etc/rsyslog.conf" "/etc/syslog.conf" "/etc/syslog-ng.conf")
	file_exists_count=0
	for ((i=0; i<${#syslogconf_files[@]}; i++))
	do
		if [ -f ${syslogconf_files[$i]} ]; then
			((file_exists_count++))
			syslogconf_file_owner_name=`ls -l ${syslogconf_files[$i]} | awk '{print $3}'`
			if [[ $syslogconf_file_owner_name =~ root ]] || [[ $syslogconf_file_owner_name =~ bin ]] || [[ $syslogconf_file_owner_name =~ sys ]]; then
				syslogconf_file_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
				if [ $syslogconf_file_permission -le 640 ]; then
					syslogconf_file_owner_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
					if [ $syslogconf_file_owner_permission -eq 6 ] || [ $syslogconf_file_owner_permission -eq 4 ] || [ $syslogconf_file_owner_permission -eq 2 ] || [ $syslogconf_file_owner_permission -eq 0 ]; then
						syslogconf_file_group_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
						if [ $syslogconf_file_group_permission -eq 4 ] || [ $syslogconf_file_group_permission -eq 2 ] || [ $syslogconf_file_group_permission -eq 0 ]; then
							syslogconf_file_other_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
							if [ $syslogconf_file_other_permission -ne 0 ]; then
								#echo "※ U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								#echo " ${syslogconf_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								 U_21_1=1
							fi
						else
							#echo "※ U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${syslogconf_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							 U_21_1=1
						fi
					else
						#echo "※ U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " ${syslogconf_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						 U_21_1=1
					fi
				else
					#echo "※ U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " ${syslogconf_files[$i]} 파일의 권한이 640보다 큽니다." >> $resultfile 2>&1
					 U_21_1=1
				fi
			else
				#echo "※ U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " ${syslogconf_files[$i]} 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다." >> $resultfile 2>&1
				 U_21_1=1
			fi
		fi
	done
	IS_VUL=$U_21_1
		cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-21",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_21_1": $U_21_1,
    },
    "timestamp": "$DATE"
  }
}
EOF