#!/bin/bash

bold='\e[1m'
red='\e[31m'
green='\e[32m'
yellow='\e[33m'
blue='\e[34m'
stop='\e[0m'

if [ -z ${1} ]
then
	echo -e "${red}[!] ${green}Usage: ${0} google.com" && exit

else
	export domain=${1}

fi

echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}subfinder${blue}"
subfinder -d ${domain} | tee domains.txt

echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}assetfinder${blue}"
assetfinder -subs-only ${domain} | tee -a domains.txt

echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}amass${blue}"
amass enum -brute -d ${domain} | tee -a domains.txt

echo -e "${bold}${yellow}[*] ${red}Removing duplicates from the domain list${blue}"

cat domains.txt | sort -u | tee -a list.txt

mv list.txt domains.txt

echo -e "${bold}${yellow}[*] ${red}Adding protocols with subdomains & saving into hosts.txt${stop}"
cat domains.txt | httprobe | tee -a hosts.txt


# add "/" after domains, for smuggler tool
#awk '{print $0, "/"}' hosts.txt > target
#sleep 1
#cat target | tr -d " \t\r" | tee hosts.txt
#rm target && rm list.txt

echo -e "${bold}${yellow}[+]${green}Process complete${stop}"
sleep 1
echo -e "${bold}${yellow}[*]${green}Found $(cat domains.txt | wc -l) subdomains${stop}"
