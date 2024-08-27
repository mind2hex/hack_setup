#!/bin/bash

# Show messages to the terminal
log_msg(){
    # $1 = msg
    # $2 = type (ERROR, WARNING, DEBUG)
    RED="\e[31m"
    YELLOW="\e[33m"
    BLUE="\e[34m"
    END_COLOR="\e[0m"

    if [[ $2 == "ERROR" ]];then
        COLOR="${RED}"
    elif [[ $2 == "WARNING" ]];then
        COLOR="${YELLOW}"
    elif [[ $2 == "DEBUG" ]];then
        COLOR="${BLUE}"
    else
        COLOR="${END_COLOR}"
    fi

    echo -n "---------------------------------------------------"
    echo -e "\n[!] ${COLOR} $@ ${END_COLOR}"
}

# Function to detect distribution and package manager
detect_package_manager(){
    if [[ -f /etc/debian_version ]];then
        PACKAGE_MANAGER="apt-get"
        PACKAGE_MANAGER_UPDATE="apt-get update"
        PACKAGE_MANAGER_UPGRADE="apt-get upgrade -y"
        PACKAGE_MANAGER_INSTALL="apt-get install -y"
        PACKAGE_MANAGER_UNINSTALL="apt-get remove"
    elif [[ -f /etc/redhat-release  ]];then
        PACKAGE_MANAGER="yum"
        PACKAGE_MANAGER_UPDATE="yum update"
        PACKAGE_MANAGER_UPGRADE="yum upgrade"
        PACKAGE_MANAGER_INSTALL="yum install"
        PACKAGE_MANAGER_UNINSTALL="yum remove"
    elif [[ -f /etc/arch-release ]];then
        PACKAGE_MANAGER="pacman"
        PACKAGE_MANAGER_UPDATE="pacman -Syu"
        PACKAGE_MANAGER_UPGRADE=${PACKAGE_MANAGER_UPDATE}
        PACKAGE_MANAGER_INSTALL="pacman -S --noconfirm"
        PACKAGE_MANAGER_UNINSTALL="pacman -R"
    else
        log_msg "Distribution not supported." "ERROR"
        exit 1
    fi

    log_msg "Packet manager detected: ${PACKAGE_MANAGER}"
}

# Function to update and upgrade before installing other tools
update_upgrade(){
    log_msg "Updating system: ${YELLOW}${PACKAGE_MANAGER_UPDATE}${END_COLOR}"
    sleep 2
    sudo ${PACKAGE_MANAGER_UPDATE}
    if [[ $? -ne 0 ]];then
        log_msg "Unable to update using ${PACKAGE_MANAGER_UPDATE}" "ERROR"
        exit 1
    fi

    log_msg "Upgrading system: ${YELLOW}${PACKAGE_MANAGER_UPGRADE}${END_COLOR}"
    sleep 2
    sudo ${PACKAGE_MANAGER_UPGRADE}
    if [[ $? -ne 0 ]];then
        log_msg "Unable to upgrade using ${PACKAGE_MANAGER_UPGRADE}" "ERROR"
        exit 1
    fi
}

# Setup directories for tools and proyects
setup_directories(){
    pentest_dir="${HOME}/PENTEST"
    dev_dir="${pentest_dir}/dev/"
    github_dir="${pentest_dir}/github/"
    wordlist_dir="/usr/share/wordlists/"

    directories=(
        ${dev_dir}
        ${github_dir}/{my_tools,cloned_tools}
        ${dev_dir}/{python,c++,bash,web,nasm}
    )

    privileged_directories=(
        ${wordlist_dir}
    )
    
    log_msg "Creating special directories"
    for directory in ${directories[@]};do
        echo -e "\t- ${directory}"
        mkdir -p ${directory}
    done

    log_msg "Creating privileged special directories"
    for directory in ${privileged_directories[@]};do
        echo -e "\t- ${directory}"
        sudo mkdir -p ${directory}
    done
}

# install tools using different resources (github, extern pages, package repositories, etc)
install_tools(){
    install_tools_with_pkg_manager(){
        # $1 tools category
        log_msg "Do you want to install ${YELLOW}$1${END_COLOR}?\n${tools[@]}"
        read -p "[y/n]: " choice
        if [[ "${choice}" = "y" ]];then
            for tool in ${tools[@]}; do
                echo -e -n "\t -> Installing $tool..."
                sudo $PACKAGE_MANAGER_INSTALL $tool >/dev/null 2>&1
                if [[ $? -eq 0 ]];then
                    echo "Done"
                else
                    echo "Failed"
                fi
            done
        fi
    }

    install_tools_from_github(){
        for tool_url_path in ${github_tools[@]};do
            
            # tool name
            tool=$( echo "$tool_url_path" | cut -d "@" -f 1 )

            # tool url (github, gitlab, etc) should be a git reopsitory
            url=$( echo "$tool_url_path"  | cut -d "@" -f 2 )

            # path to where the tool will be cloned
            path=$( echo "$tool_url_path" | cut -d "@" -f 3 )
            
            if [[ -e $path ]];then
                log_msg "$tool already installed"
                continue
            fi

            # EXPLOITDB installation
            log_msg "installing $tool"
            if [[ $tool = "exploitdb" ]];then
                if ! [[ -d $path ]];then
                    # cloning tool
                    sudo git clone $url $path

                    # creating symbolic link to use exploitdb tools like searchsploit
                    sudo ln -sf ${path}/searchsploit /usr/local/bin/searchsploit

                    # copying searchsploit profile to home dir
                    cp -f ${path}/.searchsploit_rc ~/

                    # patch for searchsploit update functionality 
                    # (it updates 'master' branch when the real branch is 'main')
                    sudo sed -i 's/master/main/g' /opt/exploitdb/searchsploit 
                else 
                    echo "Already installed"
                fi 
                continue
            fi

            # LINPEAS  installation
            if [[ $tool = "linpeas.sh" ]];then
                mkdir -p $path
                curl -L "$url" > $path/linpeas.sh
                continue
            fi 

            # RTL8812AU drivers download
            if [[ $tool = "rtl8812au" ]];then
                git clone $url $path
                # execute compilation process here...
            fi

            if [[ $tool = "rockyou.txt" ]];then
                sudo wget "$url" -O "$path"
            fi

            # normal clonning
            git clone $url $path || sudo git clone $url $path
            
        done
    }

    # tools categories here, add or delete tools if needed
    programming_tools=( python3 python3-venv python3-pip emacs git gdb )
    virtualization_tools=( qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager )
    container_tools=( docker.io docker-compose )
    system_tools=( build-essential terminator conky-all neofetch htop tree openssh-server )
    network_analysis_tools=( wireshark netdiscover arping )
    network_security_tools=( aircrack-ng reaver bettercap nmap )
    radio_tools=( gnuradio gqrx-sdr rtl-sdr hackrf )
    web_security_tools=( wfuzz sqlmap openssl )
    anonymity_tools=( tor torbrowser-launcher proxychains4 macchanger )
    cracking_tools=( hydra john hashcat hashcat-nvidia hcxtools crunch )
    malware_detection_tools=( rkhunter chkrootkit clamav )
    binary_analysis_tools=( binwalk )

    github_tools=(
        exploitdb@https://gitlab.com/exploit-database/exploitdb.git@/opt/exploitdb
        webToolkit@https://github.com/mind2hex/webtoolkit@${github_dir}/my_tools/webToolkit
        NetRunner@https://github.com/mind2hex/NetRunner@${github_dir}/my_tools/NetRuner
        TCPCobra@https://github.com/mind2hex/TCPCobra@${github_dir}/my_tools/TCPCobra
        Hackpack_usb@https://github.com/mind2hex/Hackpack_usb@${github_dir}/my_tools/Hackpack_usb
        linpeas.sh@https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh@${github_dir}/cloned_tools/LinPeas/
        rtl8812au@https://github.com/aircrack-ng/rtl8812au.git@${github_dir}/cloned_tools/rtl8812au
        SecLists@https://github.com/danielmiessler/SecLists@${wordlist_dir}/SecLists
        rockyou.txt@https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt@${wordlist_dir}/rockyou.txt
        FuzzDB@https://github.com/fuzzdb-project/fuzzdb@${wordlist_dir}/FuzzDB
    )

    categories=(
        programming_tools
        virtualization_tools
        container_tools
        system_tools
        network_analysis_tools
        network_security_tools
        radio_tools
        web_security_tools
        anonymity_tools
        cracking_tools
        malware_detection_tools
        binary_analysis_tools
    )

    for category in ${categories[@]};do
        # creating reference with the array of the category
        declare -n ref=$category
        tools=( ${ref[@]} )
        install_tools_with_pkg_manager $category

        # programming_tools configuration here
        if [[ "${category}" = "programming_tools" && "${choice}" = "y" ]];then
            # python libraries
            $PACKAGE_MANAGER_INSTALL python3-scapy 
            $PACKAGE_MANAGER_INSTALL python3-pwntools 
            $PACKAGE_MANAGER_INSTALL python3-requests 
            $PACKAGE_MANAGER_INSTALL python3-pycrypto 
        fi
        
        # virtualization_tools configuration here
        if [[ $category = "virtualization_tools" && "${choice}" = "y" ]];then
            # add user to libvirt group to manage virtual machines without root permissions
            sudo adduser $(whoami) libvirt
            sudo adduser $(whoami) kvm
        fi

        # container_tools configuration here
        if [[ $category = "container_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # system_tools configuration here
        if [[ $category = "system_tools" && "${choice}" = "y" ]];then
            # conky configuration
            mkdir -p ${HOME}/.config/conky/
            cp ./conky.conf ${HOME}/.config/conky/            

            # neofetch configuration
            if [[ -z $( grep -m 1 -o "neofetch" ~/.bashrc ) ]];then
                echo -e "\nneofetch" >> ~/.bashrc
            fi
        fi

        # network_analysis_tools configuration here
        if [[ $category = "network_analysis_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # network_security_tools configuration here
        if [[ $category = "network_security_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # radio_tools configuration here
        if [[ $category = "radio_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # web_security_tools configuration here
        if [[ $category = "web_security_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # anonymity_tools configuration here
        if [[ $category = "anonymity_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # cracking_tools configuration here
        if [[ $category = "cracking_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # malware_detection_tools configuration here
        if [[ $category = "malware_detection_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

        # binary_analysis_tools configuration here
        if [[ $category = "binary_analysis_tools" && "${choice}" = "y" ]];then
            echo -n "" 
        fi

    done

    install_tools_from_github

    # extern tools resources:
    # code (visualstudiocode) https://code.visualstudio.com/
    # kismet https://www.kismetwireless.net/packages/
    # gobuster https://github.com/OJ/gobuster
    # bettercap https://www.bettercap.org/
}

additional_configurations(){
    # setting up bash_aliases
    aliases_path="./bash_aliases.sh"    
    log_msg "Copying ${aliases_path} to ~/.bash_aliases"
    cp -f ${aliases_path} ~/.bash_aliases
    if [[ -z $( grep ". ~/.bash_aliases" ~/.bashrc ) ]];then
        echo -e "\n. ~/.bash_aliases" >> ~/.bashrc
    fi

    # setting up bash functions
    functions_path="./bash_functions.sh"
    log_msg "Copying ${functions_path} to ~/.bash_functions"
    cp -f ${functions_path} ~/.bash_functions
    if [[ -z $( grep -o ". ~/.bash_functions" ~/.bashrc ) ]];then
        echo -e "\n. ~/.bash_functions" >> ~/.bashrc
    fi

    # setting up hosts
    log_msg "Adding wifi pineapple address to /etc/hosts"
    wifi_pineapple_addr="172.16.42.1"
    hosts=$( grep -o "${wifi_pineapple_addr}" /etc/hosts )
    if [[ -z "${hosts}" ]];then
	    echo -e "${wifi_pineapple_addr}\twifi-pineapple.net\t# port 1471" | sudo tee -a /etc/hosts > /dev/null
    fi
}

main (){
    # request sudo rights once
    sudo whoami > /dev/null

    # selecting a packet manager
    detect_package_manager

    # initial update upgrade
    update_upgrade    

    # creating directory structure
    setup_directories

    # installing tools using packet manager and github
    install_tools

    # setting up bash environment.
    additional_configurations

    log_msg "DONE" "DEBUG"
}

main 

# add ngrok to tools
#  curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok