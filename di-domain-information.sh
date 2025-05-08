#!/bin/bash
#################################################################
# Script: WhoIS/Dig Script                                      #
# By: Jacob Borg                                                #
# Last updated: 08-05-2025                                      #
#################################################################

# Debugging
#set -o xtrace          # Trace the execution of the script (debug)
# Ensures that when the script is complete all temporary files created are deleted
function cleanup_main () {
  rm -f *_output_di
  rm -f *_lookup_di
  rm -f *_host_di
  rm -f *_abr_di
}
trap cleanup_main EXIT

#######################################################################
#                   COLOURING AND GREP VARIABLES                      #
#######################################################################

#--! THE VARIABLES LISTED BELOW CAN BE UPDATED TO A LIST OF FDQNS TO COLOUR OUTPUT DEPENDING ON USER REQUIREMENTS
#--! THEY CAN BE UPDATED TO SUIT WHAT THE USER REQUIRES OR REMOVED OUTRIGHT

# Colouring
GREEN='\e[92m'
YELLOW='\e[93m'
RED='\e[91m'
END='\e[0m'

# DNS servers
nameservers_check=""

# Active Hosting Servers
goodhosting_check=""

# Shut-down Legacy Servers
badhosting_check=""

# Email servers
spf_check=""

# Bad SPF lookups (used for Legacy checks)
badspf_check=""

#######################################################################
#                            SCRIPT START                             #
#######################################################################

# Function for help info
function help_info {
  echo -e "usage: di [-h] [-v] [-q] domain\n"
  echo -e "options:"
  echo -e "-h         Show brief help"
  echo -e "-v         Show verbose output"
  echo -e "-q         Skip non-critical checks & URL generation\n"
}

# Function for stripping the domain name out of a provided URL
function strip_verify_domain {
  naive_domain_regex="^[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$"
  if [[ "$1" =~ .*"@".* ]]; then
    domain=$(echo $1 | awk '{split($1,domain,"@"); print domain[2]}' | tr '[:upper:]' '[:lower:]')
  else
    domain=$(echo $1 | sed -r 's|^(https?://)?(www\.)?([a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+)(:[0-9]+)?/?.*|\3|' | tr '[:upper:]' '[:lower:]')
  fi
  [[ ! $domain =~ $naive_domain_regex ]] && echo -e "\nInvalid domain provided!" && help_info > /dev/tty  && exit 1
}

# Sets up the available arguements that can be used
verbose=false
quick=false
while getopts "hqv" opt 2>/dev/null; do
  case $opt in
    h)
      echo -e "\nThis command is used to view important domain information."
      help_info
      exit 0
      ;;

    q)
      quick=true
      ;;

    v)
      verbose=true
      ;;

    *)
      echo -e "\nUnrecognized flag!"
      echo -e "Use -h for help.\n"
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

domain=$1
nameserver=$2
if [ -z "$domain" ]; then
  echo -e "\nNo domain supplied!"
  help_info
  exit 0
fi
strip_verify_domain $domain

# Runs WHOIS and sets up variables for later use
timeout 5 whois $domain > whois_output_di & WhoIS=$!

# Setting up variables for the expected WHOIS outputs
isRootDomain=1 # assume the domain exists before proven otherwise
tld="${domain#*.}"
patterns="(domain|no) (not|match|data|entries) (found|for)|not found|nodename nor servname provided"

# Grabbing DNS records that are used throughout the script and setting up variables for them
dig +short $domain $nameserver A $domain $nameserver AAAA 2>/dev/null > A_lookup_di & Dig1=$!
dig +short www.$domain $nameserver 2>/dev/null > WWW_lookup_di & Dig2=$!
dig +short $domain $nameserver MX > MX_lookup_di & Dig3=$!
dig +short $domain $nameserver SOA > SOA_lookup_di & Dig4=$!
dig +short $domain $nameserver NS | sed 's/\.$//' | tr '[:lower:]' '[:upper:]' | sort > NS_lookup_di & Dig5=$!
wait "${Dig[@]}"

# Sets up a bunch of variables for different DIG results to be used later
ns_check=$(cat NS_lookup_di)
resolving_record_A=$(cat A_lookup_di)
resolving_record_WWW=$(cat WWW_lookup_di)
resolving_record_SOA=$(cat SOA_lookup_di)
resolving_record_MX=$(cat MX_lookup_di)

# Performs some more lookups and saves them to temp files
# We only want the IPs so we grep only for them using some regex
dig +short $resolving_record_MX $nameserver A 2>/dev/null > mx_host_di_lookup_di & mxWait=$!
dig +short -x $(egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' A_lookup_di) 2>/dev/null > server_host_di & lookup1=$!
dig +short -x $(egrep -o '([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}' A_lookup_di) 2>/dev/null > server_AAAA_host_di & lookup2=$!
dig +short -x $(egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' WWW_lookup_di) 2>/dev/null > server_www_host_di & lookup3=$!
wait $mxWait
dig +short -x $(egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' mx_host_di_lookup_di) 2>/dev/null > mail_host_di & lookup4=$!
wait "${lookup[@]}"

#######################################################################
#        Gets the important WHOIS information for the domain          #
#######################################################################

function whois_info () {
while [ -e /proc/$WhoIS ]; do sleep 0.02 ; done
whois_output=$(cat whois_output_di 2>/dev/null)
pattern_match=$(egrep -i "$patterns" whois_output_di 2>/dev/null)
registrar_check=$(grep -i --colour=never 'Synergy Wholesale' whois_output_di 2>/dev/null) # Can be updated to whatever registrar the user requires
whois_filter=$(egrep "(Registrar|Registry) WHOIS Server: \
|Status: \
|Last Modified: \
|(Creation|Updated|Expiration) Date:\
|(Registered|Expires) On:\
|Registry Expiry Date: \
|Expiration Date: \
|DNSSEC:" whois_output_di 2>/dev/null)

  echo -e "\n${YELLOW}DOMAIN INFO:${END}"
  echo -e "Domain Name: $domain"
  echo -e "URL: https://$domain/"

  echo -e "\n${YELLOW}WHOIS INFORMATION:${END}"
  # Check if the WHOIS output is empty
  if [[ -z $whois_output ]]; then
    isRootDomain=0 # Didn't return a result from the WHOIS query
    echo -e "  ${RED}WHOIS CHECK TIMED OUT!${END}"
    echo -e "  ${RED}REGISTRY MAY BE PERFORMING MAINTENANCE!${END}"
    exit
  # Check if we have a valid WHOIS server configured to check against
  elif [[ $whois_output == *"No whois server is known"* ]]; then
    isRootDomain=0
    echo -e "  ${RED}NO WHOIS SERVER FOR SPECIFIED DOMAIN FOUND!${END}"
    exit
  # Check if the au domain is under priority hold
  elif [[ $whois_output == *"Priority Hold"* ]]; then
    isRootDomain=0
    echo -e "  ${RED}DOMAIN IS CURRENTLY UNDER CONTENTION!${END}"
    echo -e "  ${RED}YOU CAN CHECK THE STATUS AT THE BELOW URL:${END}"
    echo -e "  https://www.auda.org.au/tools/priority-status-tool"
    exit
  # Checks for any other failures from the WHOIS output
  elif [[ $pattern_match ]]; then
    isRootDomain=0
    echo -e "  ${RED}ROOT DOMAIN NOT FOUND! Continuing in case of sub domain...${END}"
    exit
  fi
  # Checks if it is a .uk domain - if so it changes how it grabs the correct info from the WHOIS as .UK domains display the data differently
  if [[ $isRootDomain == 1 ]] && [[ ${tld} == *"uk" ]] && ! [[ -z $whois_output ]]; then
    echo -e $(awk -F: '/URL:/ && $0 != ""  { REGURL=$0 } END { print REGURL }' whois_output_di \
    | sed -r 's|(.*)|\1|' | sed 's|URL:|\\e[32mRegistrar URL:\\e[0m|g') | sed -r 's|^(.*)$|  \1|'
    echo -e "${GREEN}Registrar Name:${END}" $(awk -F: '/Registrar:/ && $0 != ""  { getline; REGISTRAR=$0 } END { print REGISTRAR }' whois_output_di \
    | sed -r 's|(.*)|\1|') | sed -r 's|^(.*)$|  \1|' \
    | GREP_COLOR='01;32' GREP_OPTIONS='--color=always' egrep -i "Synergy Wholesale|$"
    echo -e $(awk -F: '/Last updated:/ && $0 != ""  { LUPDATE=$0 } END { print LUPDATE }' whois_output_di \
    | sed -r 's|(.*)|\1|') | sed -r 's|^(.*)$|  \1|'
    echo -e $(awk -F: '/Registered on:/ && $0 != ""  { REGDATE=$0 } END { print REGDATE }' whois_output_di \
    | sed -r 's|(.*)|\1|') | sed -r 's|^(.*)$|  \1|'
    echo -e $(awk -F: '/Expiry date:/ && $0 != ""  { EXPDATE=$0 } END { print EXPDATE }' whois_output_di \
    | sed -r 's|(.*)|\1|') | sed -r 's|^(.*)$|  \1|'
    ns_lookup_di=$(sed -n '/Name servers:/,/WHOIS lookup/p' whois_output_di | sed '1d;$d' \
    | awk '{print $1}' | tr '[:lower:]' '[:upper:]' | sort)
  fi

  # Gets the appropriate fields from the WHOIS output and colours the different statuses
  if [[ $isRootDomain == 1 ]] && ! [[ -z $whois_filter ]]; then
    export GREP_OPTIONS='-i --color=always'
    # Checks if its a ro domain
    if [[ ${tld} == "ro" ]]; then
      ns_lookup_di=$(egrep -i "nameserver:" whois_output_di | awk '{print $2}' | tr '[:lower:]' '[:upper:]' | sort)
      export GREP_OPTIONS='-i --color=always'
      echo -e "$(egrep 'Referral URL:' whois_output_di)" \
      | GREP_COLOR='01;32' egrep 'Referral URL:|$' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'

      echo -e "$(egrep '(Registrar:|Registrar Name:)' whois_output_di)" \
      | GREP_COLOR='01;32' egrep '(Registrar:|Registrar Name:)|(VentraIP|Synergy) Wholesale|$' \ # Can be updated to whatever registrar the user requires
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'
    elif [[ ${tld} == "ai" ]]; then
      ns_lookup_di=$(egrep -i "name server:" whois_output_di | awk '{print $3}' | tr '[:lower:]' '[:upper:]' | sort)
      echo -e "$(egrep '(Registrar:|Registrar Name:)' whois_output_di)" \
      | GREP_COLOR='01;32' egrep '(Registrar:|Registrar Name:)|(VentraIP|Synergy) Wholesale|$' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'

    else
      ns_lookup_di=$(egrep -i "name server:" whois_output_di | awk '{print $3}' | tr '[:lower:]' '[:upper:]' | sort)
      echo -e "$(egrep 'Registrar URL:' whois_output_di)" \
      | GREP_COLOR='01;32' egrep '(Registrar URL:)|$' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'

      echo -e "$(egrep '(Registrar:|Registrar Name:)' whois_output_di)" \
      | GREP_COLOR='01;32' egrep '(Registrar:|Registrar Name:)|(VentraIP|Synergy) Wholesale|$' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'
    fi
    # Colours any relevant statuses on the domain
    echo -e "${whois_filter}" \
    | sed -e 's|DNSSEC: Inactive|DNSSEC: unsigned|g' \
    | sed -e 's|DNSSEC: Active|DNSSEC: signedDelegation|g' \
    | GREP_COLOR='01;32' egrep '(Registrar:|Registrar (URL:|Name:))|$' \
    | GREP_COLOR='01;32' egrep 'serverRenewProhibited| ok|$' \
    | GREP_COLOR='01;32' egrep 'Not Currently Eligible For Renewal|$' \
    | GREP_COLOR='01;31' egrep '(client|server)Hold|pendingDelete|(Expired)|$' \
    | GREP_COLOR='01;31' egrep 'redemptionPeriod|serverUpdateProhibited|$' \
    | GREP_COLOR='01;93' egrep 'clientRenewProhibited|$' \
    | GREP_COLOR='01;93' egrep 'server(Transfer|Delete)Prohibited|$' \
    | GREP_COLOR='01;32' egrep '(VentraIP|Synergy) Wholesale|$' \ # Can be updated to whatever registrar the user requires
    | GREP_COLOR='01;32' egrep 'unsigned|$' \
    | GREP_COLOR='01;31' egrep 'signedDelegation|$' \
    | sed -E 's|([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})Z|\1 \2|g' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'
    export GREP_OPTIONS='--color=auto'
  fi

  ns_check=$(cat NS_lookup_di)
  # Checks the nameservers set at the registry and compares to what is shown from a DIG
  # This is an important check as if the IPs the nameservers set on the registry dont match those when appearing on a DIG - it can cause issues with DNS propagation. 
  # If they dont match, it will colour the nameservers set on the registry as RED to indicate an issue
  
  for var in ${ns_lookup_di[@]}; do
    dig +short ${var} A
  done > ns1_output_di & NS_wait1=$!
  for var in ${ns_check[@]}; do
    dig +short ${var} A
  done > ns2_output_di & NS_wait2=$!
  wait "${NS_wait[@]}"

  ns_lookup2=$(cat ns1_output_di | sort)
  ns_check2=$(cat ns2_output_di | sort)
  if [[ $ns_lookup2 != $ns_check2 ]]; then
    for var in ${ns_lookup_di[@]}; do
      echo -e "Name Server: ${RED}${var}${END}" \
      | sed -r 's|^(.*)$|  \1|';
    done | sort
  else
    for var in ${ns_lookup_di[@]}; do
      echo -e "Name Server: ${GREEN}${var}${END}" \
      | sed -r 's|^(.*)$|  \1|';
    done | sort
  fi

}

#######################################################################
#          Gets the domains eligibility and registrant info           #
#######################################################################
function reg_info () {
while [ -e /proc/$WhoIS ]; do sleep 0.02 ; done
whois_output=$(cat whois_output_di 2>/dev/null)
pattern_match=$(egrep -i "$patterns" whois_output_di 2>/dev/null)
if [[ -z $whois_output ]] || [[ $pattern_match ]] || \
 [[ $whois_output == *"Priority Hold"* ]] || \
 [[ $whois_output == *"No whois server is known"* ]]; then
    isRootDomain=0 # Didn't return a result from the WHOIS query
fi
whois_filter2=$(egrep "Registrant:|$ \
|Registrant Contact Name: \
|Registrant Name:" whois_output_di 2>/dev/null)

if [[ ${tld} == "ai" ]]; then
whois_filter2=$(egrep "RegistrantName:|$ \
|Registry RegistrantID: \
|RegistrantEmail:" whois_output_di \
| sed -e 's|Registrant|Registrant |g' 2>/dev/null)
fi

egrep "Registrant (ID:|Email:) \
|Eligibility (ID:|Type:|Name)" whois_output_di 2>/dev/null > whois_filter_output_di

 # Function for getting the status from the ABR lookup
 function abn_info () {
   sed -r 's/[ \t]*//g' registrant_output_di \
   | sed -r 's/(.*:[A-Z]*)//g' \
   | awk '{print "https://abr.business.gov.au/ABN/View?id=" $1}' > url_abr_di

   timeout 2 curl -s -4 "$(cat url_abr_di)" \
   | egrep '(Active|Cancelled) from' > abr_output_di

   if [[ -s abr_output_di ]]; then
     sed -r 's/(<.*>)(.*)(<.*>)/\2/g' abr_output_di | sed -r 's|^(.*)$|  \1|' jborg >> \
     | sed -r 's/(&nbsp;)(.*)(&nbsp;)/ \2 /' \
     | sed -r 's/^[ \t]*//' > filter_abr_di

     echo -e $(cat filter_abr_di \
     | sed -r 's|Active|\\e[92mActive\\e\[0m|' \
     | sed -r 's|Cancelled|\\e[91mCancelled\\e\[0m|' \
     | sed -r 's|(.*)|\1\\n|') \
     | sed -r 's|^ (.*)$|\1|'
   fi
 }
  # A huge fucking mess
  # Gets the Registrant information, checks if theres a valid ABN attached to the domain
  # Then checks against the ABR for status
  if ! [[ -z $whois_filter2 ]]; then
    echo -e "\n${YELLOW}REGISTRANT INFORMATION:${END}"
    if [[ $isRootDomain == 1 ]] && [[ ${tld} == "au" || ${tld} == "com.au" \
    || ${tld} == "net.au" || ${tld} == "org.au" ||  ${tld} == "asn.au" ]]; then
      grep "Registrant ID" whois_output_di > registrant_output_di
      abn_check=$(sed -r 's/[ \t]*//g' registrant_output_di | sed -r 's/(.*:[A-Z]*)//g')
      abn_length=${#abn_check}
      if ! [[ -s registrant_output_di ]] || ! [[ $abn_length -eq 11 ]]; then
        grep "Eligibility ID:" whois_output_di > registrant_output_di
        abn_check=$(sed -r 's/[ \t]*//g' registrant_output_di | sed -r 's/(.*:[A-Z]*)//g')
        abn_length=${#abn_check}
        if ! [[ -s registrant_output_di ]] || ! [[ $abn_length -eq 11 ]]; then
          echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
          if [[ -s whois_filter_output_di ]]; then
            echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
          fi
        else
          if [ $quick = false ]; then
            abn_info > abn_output_di
            echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
            if [[ -s abn_output_di ]]; then
              if grep -q "Registrant ID:" whois_filter_output_di; then
                echo -e "  $(egrep 'Registrant ID:' whois_filter_output_di)"
              fi
              if grep -q "Eligibility Type:" whois_filter_output_di; then
                echo -e "  $(egrep 'Eligibility Type:' whois_filter_output_di)"
              fi
              if grep -q "Eligibility Name:" whois_filter_output_di; then
                echo -e "  $(egrep 'Eligibility Name:' whois_filter_output_di)"
              fi
              echo -e "  Eligibility ID:$(cat registrant_output_di | sed 's|Eligibility ID: | |gI') >> $(cat abn_output_di)"
              echo "  $(cat url_abr_di)"
            else
              echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
            fi
          else
            echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
            echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
          fi
        fi
      else
        if [ $quick = false ]; then
          abn_info > abn_output_di
          echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
          if [[ -s abn_output_di ]]; then
            echo -e "  Registrant ID:$(cat registrant_output_di | sed 's|Registrant ID: | |gI') >> $(cat abn_output_di)"
            if grep -q "Eligibility Type:" whois_filter_output_di; then
              echo -e "  $(egrep 'Eligibility Type:' whois_filter_output_di)"
            fi
            if grep -q "Eligibility Name:" whois_filter_output_di; then
              echo -e "  $(egrep 'Eligibility Name:' whois_filter_output_di)"
            fi
            if grep -q "Eligibility ID:" whois_filter_output_di; then
              echo -e "  $(egrep 'Eligibility ID:' whois_filter_output_di)"
            fi
            echo "  $(cat url_abr_di)"
          else
            echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
          fi
        else
          echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
          echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
        fi
      fi
    else
      echo -e "${whois_filter2}" | sed -r 's|^(.*)$|  \1|'
      if [[ -s whois_filter_output_di ]]; then
        echo -e "$(cat whois_filter_output_di)" | sed -r 's|^(.*)$|  \1|'
      fi
    fi
    if [[ ${tld} == "us" ]]; then
      echo -e "$(egrep --colour=never 'Registrant Application Purpose:' whois_output_di)" \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'
      echo -e "$(egrep --colour=never 'Registrant Nexus Category:' whois_output_di)" \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed -r 's|^(.*)$|  \1|'
    fi
  fi
}

#######################################################################
#                 Gets the important DNS information                  #
#######################################################################

# A huge mess of functions for DNS record lookups and validating if the server anything resolves to is ours
# If the server is ours - checks to see if its a decomissioned legacy server or not
function dns_info () {
  export GREP_OPTIONS='-i --color=never'
  if ! [[ -z $resolving_record_A ]]; then
    server_host_di=$(egrep "$badhosting_check" server_host_di)
  fi
  if ! [[ -z $resolving_record_WWW ]]; then
    server_www_host_di=$(egrep "$badhosting_check" server_www_host_di)
  fi
  if ! [[ -z $resolving_record_MX ]]; then
    mail_host_di=$(egrep "$badhosting_check" mail_host_di)
  fi
  export GREP_OPTIONS='-i --color=always'

  function ns_check () {
    echo -e "\n${YELLOW}NAMESERVERS:${END}"
    if [[ -z $ns_check ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}"
    else
      echo -e "${GREEN}${ns_check}${END}" | sed -r 's|(.*)|  \1|'
    fi
  }

  function soa_check () {
    echo -e "\n${YELLOW}SOA RECORD:${END}"
    if [[ -z $resolving_record_SOA ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}"
    else
      echo -e "  $resolving_record_SOA" | GREP_COLOR='01;32' egrep "$nameservers_check|$"
    fi
  }

  function A_check () {
    echo -e "\n${YELLOW}A/AAAA RECORD(s)${END}"
    if [[ -z $resolving_record_A ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}"
    else
      if [[ -z $server_host_di ]]; then
        for var in ${resolving_record_A[@]}; do
          echo -e "${var} >> $(dig +short -x $var)" \
          | GREP_COLOR='01;32' egrep "$goodhosting_check|$" | sed -r 's|(.*)|  \1|'
        done
      else
        for var in ${resolving_record_A[@]}; do
          echo -e "${var} >> $(dig +short -x $var)" \
          | GREP_COLOR='01;31' egrep "$badhosting_check|$" | sed -r 's|(.*)|  \1|'
        done
        echo -e "  ${RED}DECOMISSIONED LEGACY SERVER!${END}"
      fi
    fi
  }

  function www_check () {
    echo -e "\n${YELLOW}WWW RECORD${END}"
    if [[ -z $resolving_record_WWW ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}"
    else
      wwwInfo="www.${domain} >> ${resolving_record_WWW}"
      newWwwInfo="$(echo $wwwInfo | tr '\n' ' >> ')" # Stop it going over multiple lines
      if [[ -z $server_www_host_di ]]; then
        echo -e "  $newWwwInfo>> $(cat server_www_host_di)" | GREP_COLOR='01;32' egrep "$goodhosting_check|$"
      else
        echo -e "  $newWwwInfo" | GREP_COLOR='01;31' egrep "$badhosting_check|$"
        echo -e "  ${RED}DECOMISSIONED LEGACY SERVER!${END}"
      fi
    fi
  }

  function mx_check () {
    echo -e "\n${YELLOW}MX RECORD(s)${END}"
    if [[ -z $resolving_record_MX ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}"
    else
      (echo -e "${resolving_record_MX}" | sort -n) | while IFS= read -r line; do
        mxDomain="${line##* }" # '##* ' removes the priority from the query
        if [[ "$mxDomain" == *"$domain"* ]]; then
          mailServerIP="$(dig +short $mxDomain $nameserver A $mxDomain $nameserver AAAA)"
        else
          mailServerIP="$(dig +short $mxDomain A $mxDomain AAAA)"
        fi
        mailServerIpPTR="$(dig +short -x $mailServerIP)"
        mxInfo="${line} >> $mailServerIP >> $mailServerIpPTR"
        newMxInfo="$(echo $mxInfo | tr '\n' ' >> ')" # Stop it going over multiple lines
        if [[ -z $mail_host_di ]]; then
          echo -e "${newMxInfo}" | GREP_COLOR='01;32' egrep "$goodhosting_check|$" | sed -r 's|(.*)|  \1|'
        else
          echo -e "${newMxInfo}" | GREP_COLOR='01;31' egrep "$badhosting_check|$" | sed -r 's|(.*)|  \1|'
          echo -e "  ${RED}DECOMISSIONED LEGACY SERVER!${END}"
        fi
      done
    fi
  }

  function txt_check () {
    if [ $verbose = true ]; then
      caa_check=$(dig +short $domain $nameserver CAA)
      if ! [[ -z $caa_check ]]; then
        echo -e "\n${YELLOW}CAA RECORD(s)${END}"
        echo -e "$caa_check" | sed -r 's|(.*)|  \1|'
      fi
      dmarc_check=$(dig +short _dmarc.$domain $nameserver TXT)
      if ! [[ -z $dmarc_check ]]; then
        echo -e "\n${YELLOW}DMARC RECORD${END}"
        echo -e "$dmarc_check" | sed -r 's|(.*)|  \1|'
      fi
      cpanel_dkim=$(dig +short default._domainkey.$domain $nameserver TXT)
      dedi_dkim=$(dig +short axigen._domainkey.$domain $nameserver TXT)
      google_dkim=$(dig +short google._domainkey.$domain $nameserver TXT)
      if ! [[ -z $cpanel_dkim ]] || ! [[ -z $dedi_dkim ]] || ! [[ -z $google_dkim ]]; then
        echo -e "\n${YELLOW}DKIM RECORD(s)${END}"
        if ! [[ -z $cpanel_dkim ]]; then
          echo -e "default._domainkey.$domain >>" "$cpanel_dkim" | sed -r 's|(.*)|  \1|'
        fi
        if ! [[ -z $dedi_dkim ]]; then
          echo -e "axigen._domainkey.$domain >>" "$dedi_dkim" | sed -r 's|(.*)|  \1|'
        fi
        if ! [[ -z $google_dkim ]]; then
          echo -e "google._domainkey.$domain >>" "$google_dkim" | sed -r 's|(.*)|  \1|'
        fi
      fi
    fi
    echo -e "\n${YELLOW}TXT RECORD(s)${END}"
    txtDig=$(dig +short $domain $nameserver TXT)
    spf_check1=$(egrep "$goodhosting_check" server_host_di)
    spf_check2=$(egrep "$goodhosting_check" mail_host_di)
    if [[ -z $txtDig ]]; then
      echo -e "  ${RED}DOES NOT RESOLVE!${END}\n"
    else
      echo -e "$txtDig" | GREP_COLOR='01;32' egrep -a "$spf_check|$" \
      | GREP_COLOR='01;31' egrep -a "$badspf_check|$" | sed -r 's|(.*)|  \1|'
    fi
    if ! [[ -z $server_host_di ]] || ! [[ -z $mail_host_di ]]; then
      echo -e "\n${YELLOW}WARNING${END}"
      echo -e "  ${RED}ONE OR MORE DNS RECORDS RESOLVE TO A DECOMISSIONED LEGACY SERVER!${END}"
    fi
  }

  ns_check  2>/dev/null > NS_check_output_di & Dns1=$!
  soa_check  2>/dev/null > soa_check_output_di & Dns2=$!
  A_check 2>/dev/null > A_check_output_di & Dns3=$!
  www_check 2>/dev/null > www_check_output_di & Dns4=$!
  mx_check 2>/dev/null > mx_check_output_di & Dns5=$!
  txt_check 2>/dev/null > txt_check_output_di & Dns6=$!
  wait "${Dns[@]}"

  DNS_files=(
    NS_check_output_di
    soa_check_output_di
    A_check_output_di
    www_check_output_di
    mx_check_output_di
    txt_check_output_di
  )
  for file in "${DNS_files[@]}"; do
    if [ -s "$file" ]; then
      cat "$file"
    fi
  done
  export GREP_OPTIONS='--color=auto'
}

#######################################################################
#  Generates cPanel/WHM one-click logins and a Synergy Management URL #
#######################################################################
#--! NO LONGER USABLE
# function management_urls () {
# if [ $quick = false ]; then
#   PTR_record_A=$(egrep --colour=never "$goodhosting_check" server_host_di)
#   PTR_record_AAAA=$(egrep --colour=never "$goodhosting_check" server_AAAA_host_di)
#   PTR_record_WWW=$(egrep --colour=never "$goodhosting_check" server_www_host_di)
#   PTR_record_MX=$(egrep --colour=never "$goodhosting_check" mail_host_di)
#   PTR_record_SOA=$(awk '{print $2}' SOA_lookup_di | sed -r 's|root.||g' | egrep --colour=never "$goodhosting_check")
#   # Checks if the server the records are resolving to are ours
#   if ! [[ -z $PTR_record_A ]]; then
#     int_serv=$PTR_record_A
#   elif ! [[ -z $PTR_record_AAAA ]]; then
#     int_serv=$PTR_record_AAAA
#   elif ! [[ -z $PTR_record_WWW ]]; then
#     int_serv=$PTR_record_WWW
#   elif ! [[ -z $PTR_record_MX ]]; then
#     int_serv=$PTR_record_MX
#   elif ! [[ -z $PTR_record_SOA ]]; then
#     int_serv=$PTR_record_SOA
#   fi
#   if ! [ -z $int_serv ]; then
#     # Creates cPanel & WHM login links if the cPanel server is ours
#     get_urls $domain $int_serv > cpanel_output_di
#   fi
# fi
#
# # WHOIS Information we need for the Synergy URL
# while [ -e /proc/$WhoIS ]; do sleep 0.02 ; done
# registrar_check=$(grep -i --colour=never 'Synergy Wholesale' whois_output_di 2>/dev/null)
# if [[ -s cpanel_output_di ]] || [[ -n $registrar_check ]]; then
#   echo -e "\n${YELLOW}MANAGEMENT URL(s) ${END}"
#   # Hyperlinks a Synergy URL if the domains registrar is listed as Synergy Wholesale
#   if [[ -n $registrar_check ]]; then
#     echo -e "\n  ${YELLOW}SYNERGY MANAGEMENT URL${END}"
#     echo -e "  https://manage.synergywholesale.com/home/search?s=~$domain"
#   fi
# fi
}
#--!
#######################################################################
#          Puts it all together and prints output all at once         #
#######################################################################

# Runs all the different functions at once in the background - this significantly improves the time to execute the whole script
#management_urls > management_urls_output_di & End1=$!
whois_info > whois_info_output_di & End2=$!
reg_info > reg_info_output_di $ End3=$!
dns_info > dns_info_output_di & End4=$!
wait "${End[@]}"

output_files=(
  whois_info_output_di
  reg_info_output_di
  dns_info_output_di
#  management_urls_output_di
)
clear
echo
for file in "${output_files[@]}"; do
  if [ -s "$file" ]; then
    cat "$file"
  fi
done
echo

# Done!
