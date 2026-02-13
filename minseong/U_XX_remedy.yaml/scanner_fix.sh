#! /usr/bin/bash

for ((i=14; i<=33; i++))
do
echo "$i"
sudo ansible-playbook -i localhost, -c local ./U_XX_fix.yaml/U_$i"_fix".yaml
done

for ((i=44; i<=53; i++))
do
echo "$i"
sudo ansible-playbook -i localhost, -c local ./U_XX_fix.yaml/U_$i"_fix".yaml
done