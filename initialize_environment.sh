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

parse_args(){
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        
        case $1 in
            -h|--help)
                show_help
                ;;
            --skip-update)
                SKIP_UPDATE=true
                ;;
            --skip-tools)
                SKIP_TOOLS=true
                ;;
            --skip-pkg-tools)
                SKIP_PKG_TOOLS=true
                ;;
            --skip-github-tools)
                SKIP_GITHUB_TOOLS=true
                ;;
            --skip-config)
                SKIP_CONFIG=true
                ;;
            --auto)
                AUTOMODE=true
                ;;
            -o|--output)
                if [[ -n "${2-}" && $2 != -* ]]; then
                    output_file=$2
                    shift
                else
                    error_exit "Argument for $1 is missing"
                fi
                ;;
            *)
                log_msg "Unknown option: $1" "ERROR"
                exit
                ;;
        esac
        shift
    done    

    : "${SKIP_UPDATE:=false}"
    : "${SKIP_TOOLS:=false}"
    : "${SKIP_PKG_TOOLS:=false}"
    : "${SKIP_GITHUB_TOOLS:=false}"
    : "${SKIP_CONFIG:=false}"
    : "${AUTOMODE:=false}"

}

show_help(){
    echo "Usage: ./initialize_environment.sh [options]"
    echo "Options:"
    echo "   -h, --help          show this help message"
    echo "   --skip-update       skip update/upgrade step"
    echo "   --skip-pkg-tools    skip pkg tool installation"
    echo "   --skip-github-tools skip github tool installation"
    echo "   --skip-config       skip additional configurations"
    echo "   --auto              install all tools without asking"
    exit
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
    wordlist_dir="${pentest_dir}/wordlists/"

    directories=(
        ${dev_dir}
        ${github_dir}/{my_tools,cloned_tools}
        ${docker_dir}
        ${dev_dir}/{python,c,cpp,bash,web,nasm,docker}
        ${wordlist_dir}
    )

    log_msg "Creating working directories"
    for directory in ${directories[@]};do
        echo -e "\t- ${directory}"
        mkdir -p ${directory}
    done
}

# install tools using different resources (github, extern pages, package repositories, etc)
install_tools(){
    install_tools_with_pkg_manager(){
        for category in "${!categories[@]}"; do
            log_msg "Do you want to install ${YELLOW}${category}${END_COLOR}?\n${categories[$category]}"

            if [[ "${AUTOMODE}" != "true" ]];then
                read -p "[y/n]: " choice
            else
                choice="y"
            fi

            if [[ "${choice}" == "y" || "${choice}" == "Y" ]];then
                sudo $PACKAGE_MANAGER_INSTALL ${categories[$category]}

                # aditional configurations                 
                case $category in
                    "virtualization")
                        sudo adduser $(whoami) libvirt
                        sudo adduser $(whoami) kvm
                        ;;
                    "administration")
                        # conky configuration
                        mkdir -p ${HOME}/.config/conky/
                        cp ./conky.conf ${HOME}/.config/conky/
                        if ! [[ -e $HOME/.config/autostart/conky.desktop ]];then
                            echo -e "[Desktop Entry]\nType=Application\nExec=conky -d -p 6\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\nName=Conky\nComment=System monitor" > $HOME/.config/autostart/conky.desktop
                        fi
                        # neofetch configuration
                        if [[ -z $( grep -m 1 -o "neofetch" ${HOME}/.bashrc ) ]];then
                            echo -e "\nneofetch" >> ${HOME}/.bashrc
                        fi
                        ;;
                esac
            fi

        done
    }

    install_tools_from_github(){
        for tool_url_path in ${github_tools[@]};do
            
            # tool url (github, gitlab, etc) should be a git reopsitory
            url=$( echo "$tool_url_path"  | cut -d "@" -f 1 )

            # path to where the tool will be cloned
            path=$( echo "$tool_url_path" | cut -d "@" -f 2 )

            # tool name
            tool=$( basename $path )
            
            if [[ -e $path ]];then
                log_msg "$url already installed"
                continue
            fi

            # EXPLOITDB installation
            log_msg "installing $url"
            case $tool in
                "exploitdb")
                    if ! [[ -d $path ]];then
                        # cloning tool
                        sudo git clone $url $path

                        # creating symbolic link to use exploitdb tools like searchsploit
                        sudo ln -sf ${path}/searchsploit /usr/local/bin/searchsploit

                        # copying searchsploit profile to home dir
                        cp -f ${path}/.searchsploit_rc ${HOME}/

                        # patch for searchsploit update functionality 
                        # (it updates 'master' branch when the real branch is 'main')
                        sudo sed -i 's/master/main/g' ${path}/searchsploit 
                    else 
                        echo "Already installed"
                    fi
                    ;;
                "linpeas.sh")
                    mkdir -p $path
                    curl -L "$url" > $path/linpeas.sh
                    ;;
                "rtl8812au")
                    git clone $url $path
                    # execute compilation process here...
                    ;;
                "rockyou.txt")
                    wget "$url" -O "$path"
                    ;;
                *)
                    git clone $url $path 
            esac
        done
    }

    # tools categories here, add or delete tools if needed
    declare -A categories
    categories["development"]="python3 python3-venv python3-pip emacs git gdb"
    categories["virtualization"]="qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager"
    categories["containerization"]="docker.io docker-compose"
    categories["administration"]="build-essential terminator conky-all neofetch htop tree openssh-server"
    categories["networking"]="wireshark netdiscover arping aircrack-ng reaver bettercap nmap"
    categories["radio"]="gnuradio gqrx-sdr rtl-sdr hackrf"
    categories["web-pentesting"]="wfuzz sqlmap openssl"
    categories["anonymization"]="tor torbrowser-launcher proxychains4 macchanger"
    categories["cracking"]="hydra john hashcat hashcat-nvidia hcxtools crunch"
    categories["malware-detection"]="rkhunter chkrootkit clamav"
    categories["binary-analysis"]="binwalk ghidra"
    categories["osint"]="spiderfoot"

    github_tools=(
        https://gitlab.com/exploit-database/exploitdb.git@${github_dir}/cloned_tools/exploitdb
        https://github.com/mind2hex/webtoolkit@${github_dir}/my_tools/webtoolkit
        https://github.com/mind2hex/NetRunner@${github_dir}/my_tools/NetRunner
        https://github.com/mind2hex/TCPCobra@${github_dir}/my_tools/TCPCobra
        https://github.com/mind2hex/Hackpack_usb@${github_dir}/my_tools/Hackpack_usb
        https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh@${github_dir}/cloned_tools/LinPeas/linpeas.sh
        https://github.com/aircrack-ng/rtl8812au.git@${github_dir}/cloned_tools/rtl8812au
        https://github.com/danielmiessler/SecLists@${wordlist_dir}/SecLists
        https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt@${wordlist_dir}/rockyou.txt
        https://github.com/fuzzdb-project/fuzzdb@${wordlist_dir}/FuzzDB
        https://github.com/xiv3r/Burpsuite-Professional@${github_dir}/cloned_tools/BurpPro
    )

    if ! [[ $SKIP_PKG_TOOLS == "true" ]];then
        install_tools_with_pkg_manager
    fi

    if ! [[ $SKIP_GITHUB_TOOLS == "true" ]];then
        install_tools_from_github
    fi

    # extern tools resources:
    # code (visualstudiocode) https://code.visualstudio.com/
    # kismet https://www.kismetwireless.net/packages/
    # gobuster https://github.com/OJ/gobuster
    # bettercap https://www.bettercap.org/
}

additional_configurations(){
    # setting up bash_aliases
    log_msg "Copying ./bash_aliases.sh to ${HOME}/.bash_aliases"
    cp -f ./bash_aliases.sh ${HOME}/.bash_aliases
    if [[ -z $( grep ". ${HOME}/.bash_aliases" ${HOME}/.bashrc ) ]];then
        echo -e "\n. ${HOME}/.bash_aliases" >> ${HOME}/.bashrc
    fi

    # setting up bash functions
    log_msg "Copying ./bash_functions.sh to ${HOME}/.bash_functions"
    cp -f ./bash_functions.sh ${HOME}/.bash_functions
    if [[ -z $( grep -o ". ${HOME}/.bash_functions" ${HOME}/.bashrc ) ]];then
        echo -e "\n. ${HOME}/.bash_functions" >> ${HOME}/.bashrc
    fi

    # setting up hosts
    log_msg "Adding wifi pineapple address to /etc/hosts"
    declare -A tool_addresses
    tool_addresses["wifi-pineapple"]="172.16.42.1"
    tool_addresses["bash-bunny"]="172.16.64.64"
    tool_addresses["lan-turtle"]="172.16.84.1"
    for tool in "${!tool_addresses[@]}";do
        if [[ -z $(grep -m 1 "${tool_addresses[$tool]}" /etc/hosts) ]];then
            echo -e "${tool_addresses[$tool]}\t$tool" | sudo tee -a /etc/hosts
        else 
            echo -e "${tool_addresses[$tool]}\t$tool"
        fi
    done
}

main (){
    parse_args $@

    # request sudo rights once
    log_msg "requesting sudo rights" "DEBUG"
    sudo whoami > /dev/null

    # selecting a packet manager
    detect_package_manager

    # initial update upgrade
    if ! [[ $SKIP_UPDATE == "true" ]];then
        update_upgrade    
    fi

    # creating directory structure
    setup_directories

    # installing tools using packet manager and github
    install_tools

    # setting up bash environment.
    if ! [[ $SKIP_CONFIG == "true" ]];then
        additional_configurations
    fi

    log_msg "DONE" "DEBUG"
}

main $@

# add ngrok to tools
#  curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok