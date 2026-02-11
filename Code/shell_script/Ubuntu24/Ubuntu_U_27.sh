#!/usr/bin/bash 
##### [U-27] $HOME/.rhosts, hosts.equiv 사용 금지
####### 점검내용: $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : rlogin, rsh, rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600을 초과한 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 “+” 설정이 존재하는 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_27_1=0


#echo " 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우" >> $resultfile 2>&1
	#echo " 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우" >> $resultfile 2>&1
	#echo " 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 ‘+’ 설정이 없는 경우" >> $resultfile 2>&1
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	user_homedirectory_owner_name2=() # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 저장할 빈 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name2[${#user_homedirectory_owner_name2[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_owner_name2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=${user_homedirectory_owner_name2[$i]} # 두 개의 배열 합침
	done
	r_command=("rsh" "rlogin" "rexec" "shell" "login" "exec")
	# /etc/xinetd.d 디렉터리 내 r command 파일 확인함
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${r_command[$i]} ]; then
				etc_xinetdd_rcommand_disable_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${r_command[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $etc_xinetdd_rcommand_disable_count -eq 0 ]; then
					if [ -f /etc/hosts.equiv ]; then
						etc_hostsequiv_owner_name=`ls -l /etc/hosts.equiv | awk '{print $3}'`
						if [[ $etc_hostsequiv_owner_name =~ root ]]; then
							etc_hostsequiv_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
							if [ $etc_hostsequiv_permission -le 600 ]; then
								etc_hostsequiv_owner_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
								if [ $etc_hostsequiv_owner_permission -eq 6 ] || [ $etc_hostsequiv_owner_permission -eq 4 ] || [ $etc_hostsequiv_owner_permission -eq 2 ] || [ $etc_hostsequiv_owner_permission -eq 0 ]; then
									etc_hostsequiv_group_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
									if [ $etc_hostsequiv_group_permission -eq 0 ]; then
										etc_hostsequiv_other_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
										if [ $etc_hostsequiv_other_permission -eq 0 ]; then
											etc_hostsequiv_plus_count=`grep -vE '^#|^\s#' /etc/hosts.equiv | grep '+' | wc -l`
											if [ $etc_hostsequiv_plus_count -gt 0 ]; then
												#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
												 U_27_1=1
											fi
										else
											#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											  U_27_1=1
										fi
									else
										#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										  U_27_1=1
									fi
								else
									#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									  U_27_1=1
								fi
							else
								#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
								  U_27_1=1
							fi
						else
							#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
							  U_27_1=1
						fi
					fi
					# 사용자 홈 디렉터리 내 .rhosts 파일 확인함
					for ((j=0; j<${#user_homedirectory_path[@]}; j++))
					do
						if [ -f ${user_homedirectory_path[$j]}/.rhosts ]; then
							user_homedirectory_rhosts_owner_name=`ls -l ${user_homedirectory_path[$j]}/.rhosts | awk '{print $3}'`
							if [[ $user_homedirectory_rhosts_owner_name =~ root ]] || [[ $user_homedirectory_rhosts_owner_name =~ ${user_homedirectory_owner_name[$j]} ]]; then
								user_homedirectory_rhosts_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
								if [ $user_homedirectory_rhosts_permission -le 600 ]; then
									user_homedirectory_rhosts_owner_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
									if [ $user_homedirectory_rhosts_owner_permission -eq 6 ] || [ $user_homedirectory_rhosts_owner_permission -eq 4 ] || [ $user_homedirectory_rhosts_owner_permission -eq 2 ] || [ $user_homedirectory_rhosts_owner_permission -eq 0 ]; then
										user_homedirectory_rhosts_group_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
										if [ $user_homedirectory_rhosts_group_permission -eq 0 ]; then
											user_homedirectory_rhosts_other_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
											if [ $user_homedirectory_rhosts_other_permission -eq 0 ]; then
												user_homedirectory_rhosts_plus_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$j]}/.rhosts | grep '+' | wc -l`
												if [ $user_homedirectory_rhosts_plus_count -gt 0 ]; then
													#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
													#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
													  U_27_1=1
												fi
											else
												#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
												  U_27_1=1
											fi
										else
											#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											 U_27_1=1 
										fi
									else
										#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										  U_27_1=1
									fi
								else
									#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
									  U_27_1=1
								fi
							else
								#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
								  U_27_1=1
							fi
						fi
					done
				fi
			fi
		done
	fi
	# /etc/inetd.conf 파일 내 r command 서비스 확인함
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			if [ `grep -vE '^#|^\s#' /etc/inetd.conf | grep  ${r_command[$i]} | wc -l` -gt 0 ]; then
				if [ -f /etc/hosts.equiv ]; then
					etc_hostsequiv_owner_name=`ls -l /etc/hosts.equiv | awk '{print $3}'`
					if [[ $etc_hostsequiv_owner_name =~ root ]]; then
						etc_hostsequiv_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
						if [ $etc_hostsequiv_permission -le 600 ]; then
							etc_hostsequiv_owner_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
							if [ $etc_hostsequiv_owner_permission -eq 6 ] || [ $etc_hostsequiv_owner_permission -eq 4 ] || [ $etc_hostsequiv_owner_permission -eq 2 ] || [ $etc_hostsequiv_owner_permission -eq 0 ]; then
								etc_hostsequiv_group_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
								if [ $etc_hostsequiv_group_permission -eq 0 ]; then
									etc_hostsequiv_other_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
									if [ $etc_hostsequiv_other_permission -eq 0 ]; then
										etc_hostsequiv_plus_count=`grep -vE '^#|^\s#' /etc/hosts.equiv | grep '+' | wc -l`
										if [ $etc_hostsequiv_plus_count -gt 0 ]; then
											#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
											  U_27_1=1
										fi
									else
										#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										  U_27_1=1
									fi
								else
									#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									  U_27_1=1
								fi
							else
								#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								  U_27_1=1
							fi
						else
							#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
							  U_27_1=1
						fi
					else
						#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
						 U_27_1=1 
					fi
				fi
				# 사용자 홈 디렉터리 내 .rhosts 파일 확인함
				for ((j=0; j<${#user_homedirectory_path[@]}; j++))
				do
					if [ -f ${user_homedirectory_path[$j]}/.rhosts ]; then
						user_homedirectory_rhosts_owner_name=`ls -l ${user_homedirectory_path[$j]}/.rhosts | awk '{print $3}'`
						if [[ $user_homedirectory_rhosts_owner_name =~ root ]] || [[ $user_homedirectory_rhosts_owner_name =~ ${user_homedirectory_owner_name[$j]} ]]; then
							user_homedirectory_rhosts_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
							if [ $user_homedirectory_rhosts_permission -le 600 ]; then
								user_homedirectory_rhosts_owner_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
								if [ $user_homedirectory_rhosts_owner_permission -eq 6 ] || [ $user_homedirectory_rhosts_owner_permission -eq 4 ] || [ $user_homedirectory_rhosts_owner_permission -eq 2 ] || [ $user_homedirectory_rhosts_owner_permission -eq 0 ]; then
									user_homedirectory_rhosts_group_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
									if [ $user_homedirectory_rhosts_group_permission -eq 0 ]; then
										user_homedirectory_rhosts_other_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
										if [ $user_homedirectory_rhosts_other_permission -eq 0 ]; then
											user_homedirectory_rhosts_plus_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$j]}/.rhosts | grep '+' | wc -l`
											if [ $user_homedirectory_rhosts_plus_count -gt 0 ]; then
												#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
												  U_27_1=1
											fi
										else
											#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											 U_27_1=1 
										fi
									else
										#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										 U_27_1=1 
									fi
								else
									#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									  U_27_1=1
								fi
							else
								#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
								 U_27_1=1 
							fi
						else
							#echo "※ U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
							  U_27_1=1
						fi
					fi
				done
			fi
		done
	fi
	#echo "※ U-27 결과 : 양호(Good)" >> $resultfile 2>&1
	IS_VUL=$U_27_1
	cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-27",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_27_1": $U_27_1,
    },
    "timestamp": "$DATE"
  }
}
EOF	 