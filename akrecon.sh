#!/usr/bin/bash

# Simple automation script for bug bounty :)
# Coder: akr3ch
# Github: akr3ch

#--------------------
#color codes
#--------------------
bold='\e[1m'
red='\e[31m'
green='\e[32m'
yellow='\e[33m'
blue='\e[34m'
stop='\e[0m'
#--------------------


# subdomain enumeration function
subenum(){
	echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}subfinder${blue} - Passive ${stop}${red}"
	subfinder -d ${domain} 2> /dev/null | tee domains.txt

	echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}assetfinder${blue} - Passive ${stop}${red}"
	assetfinder -subs-only ${domain} 2> /dev/null | tee -a domains.txt

	echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}amass${blue} - Active [${yellow}BRUTEFORCE${blue}] ${stop}${red}"
	amass enum -brute -d ${domain} 2> /dev/null | tee -a domains.txt

	echo -e "${bold}${blue}Use all.txt for subdomains bruteforce? [y/n]"
	read -p "-> " what
	if [[ $what == "y" ]] || [[ $what == "Y" ]];then
		echo -e "${bold}${yellow}[*] ${red}Finding subdomains using ${green}puredns${blue} - Active [${yellow}BRUTEFORCE${blue}] ${stop}${red}"
		puredns bruteforce /opt/web/dns/all.txt ${domain} -r /opt/web/dns/resolvers.txt | tee -a domains.txt
	fi

	echo -e "${bold}${yellow}[*] ${red}Removing duplicates from the domain list${blue}"

	cat domains.txt | sort -u | tee -a list.txt

	mv list.txt domains.txt

	echo -e "${bold}${yellow}[*] ${red}Adding protocols with subdomains & saving them into hosts.txt file${stop}"
	cat domains.txt | sort -u | httprobe | tee -a hosts.txt

	echo -e "${bold}${yellow}[+]${green}Process complete${stop}"
	sleep 1
	echo -e "${bold}${yellow}[*]${green}Found $(cat domains.txt | wc -l) subdomains.${stop}"
}


# http request smuggling detection function
smuggling()
{
	if [[ -f ./hosts.txt ]];then
		echo -e "${bold}${yellow}[*]${green}Preparing urls for using in smuggler tool"
		# add "/" after every urls
		awk '{print $0, "/"}' hosts.txt > tmp.txt && sleep 1 && cat tmp.txt | tr -d ' ' | tee smuggle-test.txt && rm tmp.txt

		# pass the urls to http request smuggler script
		cat smuggle-test.txt | python3 /opt/bugbounty/toolbox/smuggler/smuggler.py -l smuggler.log
	else
		echo -e "${yellow}hosts.txt ${red}file not found!"
	fi
}


# Chech CORS misconfiguration
cors()
{
	if [[ -f ./corsy.json ]];then
		echo -e "${green}CORS misconfiguration might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking CORS misconfiguration"
		python3 /opt/bugbounty/CORS/Corsy/corsy.py -i hosts.txt -o corsy.json
	fi
}


# Nuclei
nuclei-auto()
{
	if [[ -f ./nuclei-info.log ]];then
		echo -e "Nuclei-info module might be already checked [ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for info${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity info -o nuclei-info.log
	fi

	if [[ -f ./nuclei-unknown.log ]];then
		echo -e "${green}nuclei-unknown module might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for unknown severity bugs${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity unknown -o nuclei-unknown.log
	fi

	if [[ -f ./nuclei-low.log ]];then
		echo -e "${green}nuclei-low module might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for low severity bugs${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity low  -o nuclei-low.log
	fi

	if [[ -f ./nuclei-medium.log ]];then
		echo -e "${green}nuclei-medium module might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for medium severity bugs${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity medium  -o nuclei-medium.log
	fi

	if [[ -f ./nuclei-high.log ]];then
		echo -e "${green}nuclei-high module might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for high severity bugs${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity high -o nuclei-high.log
	fi

	if [[ -f ./nuclei-critical.log ]];then
		echo -e "${green}nuclei-critical module might be already checked ${red}[ignoring]"
	else
		echo -e "${bold}${yellow}[*]${green}Checking for critical severity bugs${stop}"
		nuclei -l hosts.txt -H "X-Forwarded-For: 127.0.0.1" -H "Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" -severity critical  -o nuclei-critical.log
	fi
}

# gau
gauq()
{
	echo -e "${bold}${yellow}[+]${green} Going to perform an automated scanning for BXSS and SQLi on ${blue}${domain}${stop}"
	/opt/bugbounty/toolbox/bin/gau ${domain} | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a
}

# find sqli vulnerabilities
sqliz()
{
	if [[ -f ./sqli.log ]];then
		echo -e "${green}SQL vulnerability checking already processed ${red} [ignoring]"
	else
		gauq ${domain} | python3 /opt/bugbounty/SQLI/DSSS/dsss.py --user-agent="Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010725 Netscape6/6.1" | tee sqli.log
	fi
}


# find blind xss vulnerabilities
bxss()
{
	# your xss hunter address here
	address="https://akr3ch.xss.ht"
	gauq ${domain} | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b ${address}
}


log4j()
{
	echo -e "${bold}${yellow}[+]${green}Checking for log4j vulnerability${stop}"
	python3 /opt/bugbounty/toolbox/log4j-scanner/log4j-scan/log4j-scan.py -l hosts.txt | tee log4j.log
}



menu()
{
    echo -e "${blue}------------------------------------------"
	echo -e "${yellow}Usage: ${green}${0} example.com [options]"
	echo -e "${blue}------------------------------------------"
	echo -e "[ ${red}${bold}		  O P T I O N S   		${stop}${blue} ]"
	echo -e "------------------------------------------"
	echo -e "[ ${red}-all${stop}   ➜   ${green}try all available options  ${blue} ]"
	echo -e "[ ${red}-subs${stop}  ➜   ${green}subdomain enumeration only ${blue} ]"
	echo -e "[ ${red}-cors${stop}  ➜   ${green}run both subenum and CORS  ${blue} ]"
	echo -e "[ ${red}-nuc ${stop}  ➜   ${green}run both subenum and nuclei${blue} ]"
	echo -e "[ ${red}-bxss${stop}  ➜   ${green}check for blind XSS vuln   ${blue} ]"
	echo -e "[ ${red}-log4j${stop} ➜   ${green}check log4j vulnerability  ${blue} ]"
}




if [[ -z ${1} ]] || [[ ${1} == "-h" ]] || [[ ${1} == "--help" ]];then
	menu
else
	export domain=${1}
	mkdir ${domain} && cd ${domain}
	if [[ ${2} == "-subs" ]];then
		subenum
	elif [[ ${2} == "-cors" ]];then
		subenum && cors
	elif [[ ${2} == "-nuc" ]];then
		subenum && nuclei-auto
	elif [[ ${2} == "-bxss" ]];then
		bxss
	elif [[ ${2} == "-log4j" ]];then
		subenum && log4j
	elif [[ ${2} == "-all" ]];then
		subenum && cors && nuclei-auto && gauq && sqliz && bxss && smuggling
	else
		menu
	fi

fi
