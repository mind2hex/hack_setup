
#####################
##  web functions  ##
#####################
check_security_headers() {
  local url=$1
  if [[ -z "$url" ]]; then
      echo "Usage: check_security_headers <url>"
      return 1
  fi
  echo "Checking security headers for $url..."
  curl -s -D- "$url" | grep -i "Strict-Transport-Security\|X-Frame-Options\|X-XSS-Protection\|Content-Security-Policy\|X-Content-Type-Options"
}

ssl_expiry() {
  local domain=$1
  if [[ -z "$domain" ]]; then
      echo "Usage: ssl_expiry <domain>"
      return 1
  fi
  echo "Checking SSL certificate expiration for $domain..."
  echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | openssl x509 -noout -dates
}

#########################
##  network functions  ##
#########################
show_ip(){
    iface_info=$(ifconfig)
    if_name=($(echo "$iface_info" | grep -o "^[a-z0-9].*:"))
    if_addr=($(echo "$iface_info" | grep -o -E "inet [0-9\.]*" | cut -d " " -f 2))

    printf "%-20s %-10s\n" "INTERFACE" "IP ADDRESS"
    echo "--------------------------------------"
    for i in $(seq 0 ${#if_name[@]});do
        printf "%-20s %-10s\n" "${if_name[$i]}" "${if_addr[$i]}"
    done
    echo "--------------------------------------"
}

nmap_default_scan(){
  if [[ $# -eq 0 ]];then
    echo "usage: default_scan [IP|IP/CIDR|IP-IP]"
    return 1
  fi
  sudo nmap -sC -T5 -Pn -n $1
}

########################
##  crypto functions  ##
########################
generate_mem_password() {
  # memorable passwords
  local words=$1
  if [[ -z "$words" ]];then
    echo "Usage: generate_mem_password <word_count>"
    return 1
  fi
  echo $(shuf -n $words /usr/share/dict/words | tr '\n' '-' | sed 's/-$//')
}

generate_password() {
  local length=$1
  if [[ -z "$length" ]]; then
      echo "Usage: generate_password <length>"
      return 1
  fi
  tr -dc A-Za-z0-9 </dev/urandom | head -c ${length} ; echo ''
}

generate_pin() {
  local length=$1
  if [[ -z "$length" ]];then
    echo "Usage: generate_pin <length>"
    return 1
  fi
  tr -dc 0-9 </dev/urandom | head -c ${length} ; echo ''
}


######################
##  misc functions  ##
######################
nuke_everything(){
  ################ DANGER #######################
  #                       ______
  #                    .-"      "-.
  #                   /            \
  #       _          |              |          _
  #      ( \         |,  .-.  .-.  ,|         / )
  #       > "=._     | )(__/  \__)( |     _.=" <
  #      (_/"=._"=._ |/     /\     \| _.="_.="\_)
  #             "=._ (_     ^^     _)"_.="
  #                 "=\__|IIIIII|__/="
  #                _.="| \IIIIII/ |"=._
  #      _     _.="_.="\          /"=._"=._     _
  #     ( \_.="_.="     `--------`     "=._"=._/ )
  #      > _.="                            "=._ <
  #     (_/                                    \_)
  ################################################  
  echo "
  ICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9fX18KICAgICAgICAgICAgICAgICAgICAgX18s
  LX5+L34gICAgYC0tLS4KICAgICAgICAgICAgICAgICAgIF8vXywtLS0oICAgICAgLCAgICApCiAg
  ICAgICAgICAgICAgIF9fIC8gICAgICAgIDwgICAgLyAgICkgIFxfX18KLSAtLS0tLS09PT07Ozsn
  PT09PS0tLS0tLS0tLS0tLS0tLS0tLT09PTs7Oz09PS0tLS0tIC0gIC0KICAgICAgICAgICAgICAg
  ICAgXC8gIH4ifiJ+In4ifiJ+XH4ifil+Ii8KICAgICAgICAgICAgICAgICAgKF8gKCAgIFwgICgg
  ICAgID4gICAgXCkKICAgICAgICAgICAgICAgICAgIFxfKCBfIDwgICAgICAgICA+Xz4nCiAgICAg
  ICAgICAgICAgICAgICAgICB+IGAtaScgOjo+fC0tIgogICAgICAgICAgICAgICAgICAgICAgICAg
  IEk7fC58LnwKICAgICAgICAgICAgICAgICAgICAgICAgIDx8aTo6fGl8YC4KICAgICAgICAgICAg
  ICAgICAgICAgICAgKGAgXiciYC0nICIpCg==
  " | base64 -d -i 

  echo -e "\e[31mWarning: This action would delete everything.\e[0m"
  read -p " Are you sure? (yes/no): " choice
  if [ "$choice" = "yes" ]; then
    for disk in $(lsblk -dno NAME); do
      sudo shred -n 2 -v /dev/$disk
    done
  else
    echo "[x] Nuke cancelled..."
  fi
}