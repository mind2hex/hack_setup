
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


######################
##  white box func  ##
######################
find-insecure-certs(){
    certs=$(find ./ -type f \( -name "*.cer" -o -name "*.pem" -o -name "*.cert" -o -name "*.crt" \) )
    
    # openssl x509 -in {} -text -noout

    if [[ ${#certs} -eq 0 ]];then
        echo "[!] No certs found..."
        return 0
    fi

    for cert in "${certs[@]}";do
        echo "==========================================================================================="
        echo "${cert}"

        # 1️⃣ validating lifespan
        echo "[!] Validating certificate dates"
        cert_dates=( $(openssl x509 -in $cert  -noout -dates | grep -E -o "[0-9]{4}" | tr "\n" " ") )
        if [[ $(expr ${cert_dates[2]} - ${cert_dates[1]}) -gt 2 ]];then
            echo "[!] WARNING: EXPIRATION DATE GREATER THAN 2 YEARS" 
        else
            echo "[!] Secure Expiration dates: ${cert_dates[1]} - ${cert_dates[2]}"
        fi
        echo ""

        # 2️⃣ validating signing algorythm # insecure algorythms SHA-1 o MD5, 
        echo "[!] Validating signing algorythm"
        signing_algorythm=( $(openssl x509 -in $cert -noout -text | grep "Signature Algorithm" | head -1 | tr -d " " | cut -d ":" -f 2) )
        echo "[!] Signing algorythm: ${signing_algorythm}"
        echo ""

        # 3️⃣ Verificar el tamaño de la clave pública
        echo "[!] Validating public key length"
        key_length=( $(openssl x509 -in "$cert" -noout -text | grep "Public-Key" | grep -E -o "[0-9]* bit" | cut -d " " -f 1) )
        if [[ $key_length -lt 2048 ]];then
            echo "[!] WARNING: INSECURE PUBLIC KEY LENGTH $key_length"
        else
            echo "[!] Secure Key length $key_length"
        fi
        echo ""

        # 4️⃣ Verificar si es un certificado de autoridad (CA)
        echo "[!] Is CA?"
        if [[ $(openssl x509 -in "$cert" -noout -text | grep -o "CA:TRUE") == "CA:TRUE" ]];then
            echo "[!] True"
        else    
            echo "[!] False"
        fi
        echo ""

        # 5️⃣ Revisar el uso del certificado
        echo "[!] Cert Key Usage:"
        echo "[!] $(openssl x509 -in "$cert" -noout -text | grep 'Key Usage')"
        echo ""
    
        # 6️⃣ Verificar si el certificado está en una lista de CA confiables
        echo "[!] Is Trusted?"
        openssl verify "$cert"
        echo ""
    done

    echo "[!] Done"
}

find-supply-chain-files(){
    # Definir un array con los nombres de los archivos de cadenas de suministro
    supply_chain_files=(
        # Node.js
        "package.json" "package-lock.json" "yarn.lock" "pnpm-lock.yaml"
        # PHP
        "composer.lock"
        # Rust
        "Cargo.lock"
        # Ruby
        "Gemfile.lock"
        # Python
        "requirements.txt" "poetry.lock" "Pipfile.lock"
        # Go
        "go.mod" "go.sum"
        # Java/Kotlin (Gradle)
        "gradle.lockfile" "build.gradle" "build.gradle.kts"
        # Java (Maven)
        "pom.xml"
        # Scala
        "build.sbt"
        # Elixir
        "mix.lock"
        # Swift
        "Package.resolved" "Cartfile.resolved" "Podfile.lock"
        # Clojure
        "deps.edn"
        # PureScript
        "spago.dhall"
        # Nix
        "flake.lock"
        # Erlang
        "rebar.lock"
    )

    # Construir la expresión para find
    find_expr=""
    for file in "${supply_chain_files[@]}"; do
        find_expr="$find_expr -o -name \"$file\""
    done
    find_expr="${find_expr:4}"  # Eliminar el primer '-o'

    # Ejecutar el comando find
    echo "🔍 Buscando archivos de cadena de suministro en el directorio actual..."
    eval "find . -type f \\( $find_expr \\)"
}

javascript-find() {
    
    case $1 in
        "endpoints")
            echo "🔍 Buscando endpoints HTTP en diferentes frameworks..."
            
            echo -e "\n📦 Express.js (Dot Notation):"
            rg -n 'app\.(get|post|put|delete|patch|options|use|all)\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n📦 Express.js (Bracket Notation):"
            rg -n "app\[[\'\"]+(get|post|put|delete|patch|options|use|all)[\'\"]+" \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n🔄 Express Router:"
            rg -n 'router\.(get|post|put|delete|patch|options|use|all)\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n⚡ Fastify:"
            rg -n 'fastify\.(get|post|put|delete|patch|options|register|route)\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n🏗️  NestJS Decorators:"
            rg -n '@(Get|Post|Put|Delete|Patch|Options|All|Head)\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 2 -B 1

            echo -e "\n🎯 NestJS Controllers:"
            rg -n '@Controller\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 3 -B 1

            echo -e "\n🌐 Koa.js:"
            rg -n 'koa\.(get|post|put|delete|patch|options|use|all)\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n🔥 Hapi.js:"
            rg -n 'server\.route\s*\(' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 3 -B 1

            echo -e "\n⚡ Next.js API Routes:"
            rg -n 'export\s+(default\s+)?function\s+(handler|GET|POST|PUT|DELETE|PATCH)' \
                --glob 'pages/api/**/*.js' --glob 'pages/api/**/*.ts' \
                --glob 'app/api/**/*.js' --glob 'app/api/**/*.ts' \
                -A 2 -B 1

            echo -e "\n🔄 Next.js App Router:"
            rg -n 'export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)' \
                --glob 'app/**/*.js' --glob 'app/**/*.ts' \
                -A 2 -B 1

            echo -e "\n🚀 SvelteKit:"
            rg -n 'export\s+(const\s+)?(GET|POST|PUT|DELETE|PATCH|OPTIONS)' \
                --glob '**/+*.server.js' --glob '**/+*.server.ts' \
                --glob '**/+page.server.js' --glob '**/+page.server.ts' \
                -A 2 -B 1

            echo -e "\n📋 Route Definitions (Generic):"
            rg -n -i 'method\s*:\s*["\'"'"'](get|post|put|delete|patch|options)["\'"'"']|["\'"'"'](get|post|put|delete|patch|options)["\'"'"']\s*:' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n📍 Path Definitions:"
            rg -n 'path\s*:\s*["\'"'"'][^"\'"'"']+["\'"'"']|route\s*:\s*["\'"'"'][^"\'"'"']+["\'"'"']' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 1 -B 1

            echo -e "\n🔧 Custom HTTP Servers:"
            rg -n 'createServer|http\.createServer|https\.createServer' \
                --glob '*.js' --glob '*.ts' --glob '*.jsx' --glob '*.tsx' --glob '*.mjs' --glob '*.cjs' \
                -A 3 -B 1
            ;;
        "dependency-pinning")
            echo "🔍 Buscando dependencias sin pin en package.json:"
            rg '\^' --glob 'package.json'  
            ;;
        "empty-catches")
            echo "🔍 Buscando bloques catch vacíos:"
            rg -U 'catch\s*\(\s*\w+\s*\)\s*\{\s*(//[^\n]*|/\*[^*]*\*/|\s*)*\}' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "console-leaks")
            echo "🔍 Buscando potenciales leaks de información en consola:"
            rg 'console\.(error|log|warn|info)\([^)]*\b(error|exception|stack|trace|password|token|key|secret|api|auth)\b[^)]*\)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs' \
                -i
            ;;
        "log-injection")
            echo "🔍 Buscando potencial log injection:"
            rg -P '\b(console\.(log|error|warn|info)|logger\.(log|error|warn|info)|debug\.log|log)\s*\(\s*[^,)]*\s*\+\s*[^,)]*\s*\)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "risky-libraries")
            echo "🔍 Buscando uso de librerías/funciones de riesgo:"
            rg -P 'Math\.random|crypto\.pseudoRandomBytes|eval|Function|setTimeout|setInterval|document\.write|innerHTML|outerHTML|localStorage|sessionStorage|child_process|fs\.(readFile|writeFile)|process\.env|vm\.runInNewContext|JSON\.parse|yaml\.load|dangerouslySetInnerHTML' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "sql-injection")
            echo "🔍 Buscando potenciales vulnerabilidades de SQL injection:"
            rg -P '\b(query|execute|exec|prepare)\s*\(\s*[^,)]*\s*\+\s*[^,)]*\s*\)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "command-injection")
            echo "🔍 Buscando potenciales vulnerabilidades de command injection:"
            rg -P '\b(exec|spawn|eval|fork|execSync|spawnSync|execFile|execFileSync)\s*\(\s*[^,)]*\s*\+\s*[^,)]*\s*\)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "path-traversal")
            echo "🔍 Buscando potenciales vulnerabilidades de path traversal:"
            rg -P '\b(readFile|writeFile|readdir|unlink|open|access|stat|lstat)\s*\(\s*[^,)]*\s*\+\s*[^,)]*\s*\)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "xss-sinks")
            echo "🔍 Buscando sinks peligrosos para XSS:"
            rg -P '\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|Function|dangerouslySetInnerHTML)\s*=|\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|Function)\s*\(' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        "hardcoded-secrets")
            echo "🔍 Buscando secretos hardcodeados:"
            rg -i -P '\b(password|passwd|pwd|secret|key|token|api_key|apikey|access_token|auth_token|private_key|secret_key)' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs' \
                --glob '*.json' \
                --glob '*.env*'
            ;;
        "weak-crypto")
            echo "🔍 Buscando algoritmos criptográficos débiles:"
            rg -i -P '\b(md5|sha1|des|rc4|base64|btoa|atob|Math\.random|crypto\.pseudoRandomBytes)\b' \
                --glob '*.js' \
                --glob '*.ts' \
                --glob '*.jsx' \
                --glob '*.tsx' \
                --glob '*.mjs' \
                --glob '*.cjs'
            ;;
        *)
            echo "📋 Opciones disponibles:"
            echo -e "\t🌐 endpoints           - Buscar definiciones de endpoints/rutas"
            echo -e "\t📦 dependency-pinning  - Dependencias sin versión fija"
            echo -e "\t🕳️  empty-catches       - Bloques catch vacíos"
            echo -e "\t📝 console-leaks       - Información sensible en logs"
            echo -e "\t💉 log-injection       - Inyección en logs"
            echo -e "\t⚠️  risky-libraries     - Librerías/funciones de riesgo"
            echo -e "\t💾 sql-injection       - Vulnerabilidades SQL injection"
            echo -e "\t⚡ command-injection    - Vulnerabilidades command injection"
            echo -e "\t📂 path-traversal      - Vulnerabilidades path traversal"
            echo -e "\t🎭 xss-sinks           - Sinks peligrosos para XSS"
            echo -e "\t🔑 hardcoded-secrets   - Secretos hardcodeados"
            echo -e "\t🔐 weak-crypto         - Algoritmos criptográficos débiles"
            echo ""
            ;;
    esac
}

java-find(){
    case $1 in
        "endpoints")
            echo "🔍 Buscando endpoints expuestos..."
            # Separamos los patrones para evitar complejidad
            echo "--- Spring MVC Annotations ---"
            rg -P '\b(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Spring Parameters ---"
            rg -P '\b(RequestParam|PathVariable|RequestBody|ResponseBody|RequestHeader)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Controllers ---"
            rg -P '\b(RestController|Controller|WebServlet|WebFilter|WebListener)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- JAX-RS Annotations ---"
            rg -P '\b(Path|GET|POST|PUT|DELETE|PATCH|Produces|Consumes)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Servlet Methods ---"
            rg -P '\b(extends HttpServlet|doGet\(|doPost\(|doPut\(|doDelete\()\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "sql-injection")
            echo "🔍 Buscando potenciales vulnerabilidades de SQL Injection..."
            echo "--- Statement Usage ---"
            rg -P '\b(Statement\.execute|createStatement|executeQuery|executeUpdate)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- String Concatenation in SQL ---"
            rg -P '(SELECT.*\+|INSERT.*\+|UPDATE.*\+|DELETE.*\+)' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- String.format with SQL ---"
            rg -P 'String\.format.*\b(SELECT|INSERT|UPDATE|DELETE)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1 -i
            
            echo "--- Template Injection in SQL ---"
            rg -P '\$\{.*\}.*\b(SELECT|INSERT|UPDATE|DELETE)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1 -i
            ;;
            
        "xss")
            echo "🔍 Buscando potenciales vulnerabilidades XSS..."
            echo "--- DOM Manipulation ---"
            rg -P '\b(innerHTML|outerHTML|document\.write)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Response Writers ---"
            rg -P '\b(response\.getWriter|PrintWriter\.print)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Redirects and Forwards ---"
            rg -P '\b(response\.sendRedirect|forward\(|include\()\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Request Parameters ---"
            rg -P '@RequestParam.*String|@PathVariable.*String' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "weak-crypto")
            echo "🔍 Buscando implementaciones criptográficas débiles..."
            echo "--- Weak Algorithms ---"
            rg -P '\b(DES|3DES|RC4|MD5|SHA1)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Weak Cipher Modes ---"
            rg -P '\bECB\b|Cipher\.getInstance\("AES"\)' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Weak Random ---"
            rg -P '\b(Random\(\)|Math\.random)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Weak SSL/TLS ---"
            rg -P '\b(SSL_|TLS_RSA_|ALLOW_ALL_HOSTNAME_VERIFIER)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            ;;
            
        "auth-issues")
            echo "🔍 Buscando problemas de autenticación/autorización..."
            echo "--- Hardcoded Credentials ---"
            rg -P 'password.*=.*"|secret.*=.*"|key.*=.*"|token.*=.*"' \
                --glob '*.java' --color=always -n -A 1 -B 1 -i
            
            echo "--- Spring Security Annotations ---"
            rg -P '\b(@PreAuthorize|@Secured|@RolesAllowed)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Security Context ---"
            rg -P '\b(SecurityContext|Authentication|Principal)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            ;;
            
        "file-operations")
            echo "🔍 Buscando operaciones de archivo potencialmente inseguras..."
            echo "--- File Constructors ---"
            rg -P '\bnew File\(' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- File Streams ---"
            rg -P '\b(FileInputStream|FileOutputStream)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- NIO File Operations ---"
            rg -P '\b(Files\.read|Files\.write|Files\.copy|Files\.move|Paths\.get)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- User Input in File Operations ---"
            rg -P 'new File.*\b(getParameter|@RequestParam|@PathVariable)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "deserialization")
            echo "🔍 Buscando vulnerabilidades de deserialización..."
            echo "--- Java Deserialization ---"
            rg -P '\b(ObjectInputStream|readObject|readUnshared)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- XML Deserialization ---"
            rg -P '\b(XMLDecoder|fromXML)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- JSON Deserialization ---"
            rg -P '\b(Jackson.*readValue|Gson.*fromJson)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Unsafe Type Handling ---"
            rg -P '\b(@JsonTypeInfo|enableDefaultTyping)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- YAML Deserialization ---"
            rg -P '\bYaml\.load\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            ;;
            
        "xxe")
            echo "🔍 Buscando potenciales vulnerabilidades XXE..."
            rg -P '\b(DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory)\b' \
                --glob '*.java' --color=always -n -A 3 -B 1
            
            rg -P '\b(TransformerFactory|SchemaFactory|XPathFactory|XMLInputFactory)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "ssrf")
            echo "🔍 Buscando potenciales vulnerabilidades SSRF..."
            echo "--- URL Connections ---"
            rg -P '\b(URL\(|URLConnection|HttpURLConnection)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- HTTP Clients ---"
            rg -P '\b(RestTemplate|WebClient|OkHttp|Retrofit)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- User Input in URLs ---"
            rg -P 'URL.*\b(request\.|@RequestParam|@PathVariable|getParameter|getHeader)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "hardcoded-secrets")
            echo "🔍 Buscando secretos hardcodeados..."
            echo "--- In Java Files ---"
            rg -P '(password|secret|key|token|api_key|apikey).*=.*"[\w\d\+\/\=]{8,}"' \
                --glob '*.java' --color=always -n -i
            
            echo "--- In Properties Files ---"
            rg -P '(password|secret|key|token|api_key|apikey).*=.*[\w\d\+\/\=]{8,}' \
                --glob '*.properties' --glob '*.yml' --color=always -n -i
            ;;
            
        "spring-security")
            echo "🔍 Buscando configuraciones de Spring Security..."
            rg -P '\b(@EnableWebSecurity|@EnableGlobalMethodSecurity|WebSecurityConfigurerAdapter)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            rg -P '\b(antMatchers|permitAll|authenticated|hasRole|hasAuthority)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            rg -P '\b(csrf\(\)\.disable|frameOptions\(\)\.disable)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            ;;
            
        "jndi")
            echo "🔍 Buscando uso de JNDI (potencial Log4Shell)..."
            rg -P '\b(InitialContext|lookup\()\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            rg -P '\b(java:comp/env|ldap://|rmi://)\b' \
                --glob '*.java' --glob '*.properties' --glob '*.xml' --color=always -n
            
            rg -P '\$\{jndi:' \
                --glob '*.java' --glob '*.properties' --glob '*.xml' --color=always -n -A 1 -B 1
            ;;
            
        "dependency-pinning")
            echo "🔍 Buscando dependency pinning issues..."
            rg -P 'versionRange>[\s\S]*?</versionRange>' --glob 'pom.xml' -n
            rg -P '\[.*,.*\)|\(.*,.*\]' --glob 'pom.xml' -n
            rg -P '<version>(LATEST|RELEASE)</version>' --glob 'pom.xml' -n
            ;;
            
        "empty-catches")
            echo "🔍 Buscando catch blocks vacíos..."
            rg -C 10 'catch\s*\([^)]*\)\s*\{\s*\}' --glob '*.java' -n
            rg -C 5 'catch\s*\([^)]*\)\s*\{\s*//.*\s*\}' --glob '*.java' -n
            ;;
            
        "console-leaks")
            echo "🔍 Buscando información sensible en logs/consola..."
            echo "--- System.out/err ---"
            rg -P 'System\.(out|err)\.print.*\b(password|secret|key|token|auth|credential|ssn|credit|card)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1 -i
            
            echo "--- Logger Usage ---"
            rg -P '(logger\.|log\.)\w+.*\b(password|secret|key|token|auth|credential|ssn|credit|card)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1 -i
            ;;
            
        "log-injection")
            echo "🔍 Buscando potenciales Log Injection..."
            rg -P '(logger\.|log\.|System\.out\.print|System\.err\.print).*\b(request\.|@RequestParam|@PathVariable|getParameter|getHeader)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "risky-libraries")
            echo "🔍 Buscando uso de librerías riesgosas..."
            echo "--- Random/Crypto ---"
            rg -P '\b(java\.util\.Random|java\.security\.SecureRandom|javax\.crypto\.Cipher)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- XML Parsers ---"
            rg -P '\b(DocumentBuilderFactory|SAXParserFactory|TransformerFactory)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Serialization ---"
            rg -P '\b(ObjectInputStream|ObjectOutputStream|SerializationUtils)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- Script Engines ---"
            rg -P '\b(ScriptEngineManager|GroovyShell|ExpressionParser)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            
            echo "--- JSON/YAML Libraries ---"
            rg -P '\b(ObjectMapper|Gson|Yaml)\b' \
                --glob '*.java' --color=always -n -A 1 -B 1
            ;;
            
        "rce")
            echo "🔍 Buscando vulnerabilidades de ejecución de código remoto (RCE)..."
            echo "--- Process Execution ---"
            rg -P '\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.start)\b' \
                --glob '*.java' --color=always -n -A 3 -B 1
            
            echo "--- Script Engine Execution ---"
            rg -P '\b(ScriptEngineManager|ScriptEngine\.eval|GroovyShell\.evaluate)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- JavaScript Context ---"
            rg -P '\b(Context\.eval|Rhino|Nashorn)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Spring Expression Language (SpEL) ---"
            rg -P '\b(ExpressionParser|SpelExpressionParser|parseExpression|getValue)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Reflection Usage ---"
            rg -P '\b(Class\.forName|Method\.invoke|Constructor\.newInstance|getMethod|getDeclaredMethod)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Template Engines ---"
            rg -P '\b(Velocity|FreeMarker|Thymeleaf).*\b(evaluate|process|merge)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- User Input in Dangerous Operations ---"
            rg -P '(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngine\.eval).*\b(request\.|@RequestParam|@PathVariable|getParameter|getHeader)\b' \
                --glob '*.java' --color=always -n -A 3 -B 1
            
            echo "--- Command Injection Patterns ---"
            rg -P '\b(cmd|sh|bash|powershell|/bin/).*\+.*\b(request\.|@RequestParam|@PathVariable)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Dynamic Class Loading ---"
            rg -P '\b(ClassLoader\.loadClass|URLClassLoader|defineClass)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- OGNL Expression Language ---"
            rg -P '\b(Ognl\.getValue|OgnlContext|Struts)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            
            echo "--- Java Compilation at Runtime ---"
            rg -P '\b(JavaCompiler|ToolProvider\.getSystemJavaCompiler|compile)\b' \
                --glob '*.java' --color=always -n -A 2 -B 1
            ;;
            
        "prometheus")
            echo "🔍 Buscando configuración de Prometheus (potencial info disclosure)..."
            rg -p '\bprometheus\b' --glob '*.yml' -n
            rg -p 'management\.endpoints\.web\.exposure\.include' --glob '*.properties' --glob '*.yml' -n
            ;;
            
        "all")
            echo "🚀 Ejecutando análisis completo..."
            for category in endpoints sql-injection xss weak-crypto auth-issues file-operations deserialization xxe ssrf rce hardcoded-secrets spring-security jndi; do
                echo ""
                echo "==============================================="
                java-find "$category"
                echo "==============================================="
            done
            ;;
            
        *)
            echo "🛡️  java-find - Herramienta de análisis estático para Java"
            echo ""
            echo "Categorías disponibles:"
            echo -e "\t📡 endpoints           - Mapeo de endpoints REST/Web"
            echo -e "\t💉 sql-injection       - Potenciales SQL Injection"
            echo -e "\t🔥 xss                 - Potenciales XSS"
            echo -e "\t🔐 weak-crypto         - Criptografía débil"
            echo -e "\t🔑 auth-issues         - Problemas de autenticación"
            echo -e "\t📁 file-operations     - Operaciones de archivo inseguras"
            echo -e "\t📦 deserialization     - Vulnerabilidades de deserialización"
            echo -e "\t📄 xxe                 - XML External Entity"
            echo -e "\t🌐 ssrf                - Server-Side Request Forgery"
            echo -e "\t💥 rce                 - Remote Code Execution"
            echo -e "\t🔒 hardcoded-secrets   - Secretos hardcodeados"
            echo -e "\t⚡ spring-security     - Configuraciones Spring Security"
            echo -e "\t🔍 jndi                - Uso de JNDI (Log4Shell)"
            echo -e "\t📋 dependency-pinning  - Dependency pinning issues"
            echo -e "\t❌ empty-catches       - Catch blocks vacíos"
            echo -e "\t📝 console-leaks       - Info sensible en logs"
            echo -e "\t📜 log-injection       - Log injection"
            echo -e "\t📚 risky-libraries     - Librerías riesgosas"
            echo -e "\t📊 prometheus          - Configuración Prometheus"
            echo -e "\t🚀 all                 - Análisis completo"
            echo ""
            echo "Uso: java-find <categoría>"
            echo "Ejemplo: java-find rce"
            ;;
    esac
}

csharp-find() {
    case $1 in
        "endpoints")
            echo "🔍 Buscando endpoints HTTP en .NET/C#..."
            
            echo -e "\n🌐 Controllers & Actions:"
            rg -n '\[Http(Get|Post|Put|Delete|Patch|Options|Head)\]|\[Route\(|public\s+(async\s+)?(Task<)?IActionResult' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🎯 API Controllers:"
            rg -n '\[ApiController\]|ControllerBase|Controller\s*$|: Controller' \
                --glob '*.cs' \
                -A 3 -B 1

            echo -e "\n📋 Route Templates:"
            rg -n '\[Route\(["\'"'"'][^"'"'"']+["\'"'"']\)\]' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n📍 Parameter Binding:"
            rg -n '\[(FromQuery|FromBody|FromForm|FromHeader|FromRoute|FromServices)\]' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🔄 Minimal APIs (Program.cs):"
            rg -n 'app\.(Map(Get|Post|Put|Delete|Patch)|UseRouting|UseEndpoints)' \
                --glob 'Program.cs' --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🚀 SignalR Hubs:"
            rg -n ': Hub\b|HubConnectionContext' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚡ gRPC Services:"
            rg -n ': [A-Z][a-zA-Z]*\.([A-Z][a-zA-Z]*)?ServiceBase|\.proto' \
                --glob '*.cs' \
                -A 2 -B 1
            ;;
        "sql-injection")
            echo "🔍 Buscando vulnerabilidades de SQL injection:"
            
            echo -e "\n💉 String Concatenation en SQL:"
            rg -n '(ExecuteQuery|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|FromSqlInterpolated)\s*\([^)]*\+[^)]*\)|"[^"]*"\s*\+[^;]*\+[^;]*"[^"]*".*\.(ExecuteQuery|ExecuteNonQuery|ExecuteScalar)' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🔗 String Interpolation en SQL:"
            rg -n '\$"[^"]*\{[^}]+\}[^"]*".*\.(ExecuteQuery|ExecuteNonQuery|ExecuteScalar|FromSqlRaw)' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚠️  Raw SQL Commands:"
            rg -n '\b(SqlCommand|OracleCommand|MySqlCommand|NpgsqlCommand)\s*\([^)]*\+|new\s+(SqlCommand|OracleCommand)\([^)]*\{' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n📝 Dynamic LINQ:"
            rg -n '\.Where\s*\([^)]*\+[^)]*\)|\.OrderBy\s*\([^)]*\+' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🛡️  Parameterized Queries (Good):"
            rg -n 'Parameters\.Add|@\w+|SqlParameter|DbParameter' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "command-injection")
            echo "🔍 Buscando vulnerabilidades de command injection:"
            
            echo -e "\n⚡ Process.Start con Concatenación:"
            rg -n 'Process\.Start\s*\([^)]*\+[^)]*\)|ProcessStartInfo.*\+' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n💻 Cmd.exe Execution:"
            rg -n '"cmd\.exe"|"cmd".*"/c"|"powershell\.exe".*"-Command"' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🔧 Shell Command Building:"
            rg -n '\$"[^"]*\{[^}]+\}[^"]*".*Process\.Start|\$"[^"]*\{[^}]+\}[^"]*".*cmd' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🚨 Dynamic Process Arguments:"
            rg -n 'Arguments\s*=.*\+|FileName\s*=.*\+' \
                --glob '*.cs' \
                -A 2 -B 1
            ;;
        "deserialization")
            echo "🔍 Buscando vulnerabilidades de deserialización:"
            
            echo -e "\n🔓 BinaryFormatter (Muy Peligroso):"
            rg -n '\bBinaryFormatter\b|\.Deserialize\s*\(' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n📄 JSON Deserialization:"
            rg -n 'JsonConvert\.DeserializeObject|JsonSerializer\.Deserialize.*TypeNameHandling' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n📊 XML Deserialization:"
            rg -n 'XmlSerializer.*\.Deserialize|DataContractSerializer.*\.ReadObject' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚠️  Unsafe Deserialization Settings:"
            rg -n 'TypeNameHandling\.(All|Objects|Arrays)|TypeNameAssemblyFormatHandling\.Full' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🔒 Safe Deserialization (Good):"
            rg -n 'TypeNameHandling\.None|JsonSerializerOptions.*PropertyNamingPolicy' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "xss-vulnerabilities")
            echo "🔍 Buscando vulnerabilidades XSS:"
            
            echo -e "\n🔓 Raw HTML Output:"
            rg -n 'Html\.Raw\s*\(|@Html\.Raw|HtmlString|new\s+HtmlString' \
                --glob '*.cs' --glob '*.cshtml' \
                -A 1 -B 1

            echo -e "\n📝 Razor Views Sin Encoding:"
            rg -n '@\w+\s*(?!\(Html\.Encode|Html\.AttributeEncode)' \
                --glob '*.cshtml' \
                -A 1 -B 1

            echo -e "\n🎨 JavaScript Injection:"
            rg -n '<script[^>]*>.*@\w+.*</script>|Response\.Write.*<script' \
                --glob '*.cshtml' --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🛡️  HTML Encoding (Good):"
            rg -n 'Html\.Encode|Html\.AttributeEncode|HttpUtility\.HtmlEncode' \
                --glob '*.cs' --glob '*.cshtml' \
                -A 1 -B 1
            ;;
        "path-traversal")
            echo "🔍 Buscando vulnerabilidades de path traversal:"
            
            echo -e "\n📂 File Operations con User Input:"
            rg -n '(File\.(ReadAllText|WriteAllText|ReadAllLines|WriteAllLines|Open|Create)|Directory\.(GetFiles|GetDirectories))\s*\([^)]*\+[^)]*\)' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🔄 Path Combination:"
            rg -n 'Path\.Combine\s*\([^)]*\+[^)]*\)|Path\.Join.*\+' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚠️  Directory Traversal Patterns:"
            rg -n '\.\./|\.\.\\|%2e%2e|\.\.%2f|\.\.%5c' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🛡️  Path Validation (Good):"
            rg -n 'Path\.GetFullPath|Path\.IsPathRooted|Path\.GetInvalidFileNameChars' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "authentication-bypass")
            echo "🔍 Buscando bypasses de autenticación:"
            
            echo -e "\n🔓 AllowAnonymous:"
            rg -n '\[AllowAnonymous\]' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🛡️  Authorization Attributes:"
            rg -n '\[Authorize.*\]|\[RequireHttps\]' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🔑 JWT Token Validation:"
            rg -n 'TokenValidationParameters|ValidateIssuer.*false|ValidateAudience.*false|ValidateLifetime.*false' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚠️  Insecure Cookie Settings:"
            rg -n 'HttpOnly.*false|Secure.*false|SameSite.*None' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "secrets-exposure")
            echo "🔍 Buscando exposición de secretos:"
            
            echo -e "\n🔑 Hardcoded Secrets:"
            rg -ni '\b(password|secret|key|token|connectionstring)\s*[=:]\s*["\'"'"'][^"'"'"']{8,}["\'"'"']' \
                --glob '*.cs' --glob '*.json' --glob '*.config' \
                -A 1 -B 1

            echo -e "\n📋 Configuration Issues:"
            rg -n 'Configuration\[".*[Pp]assword.*"\]|Configuration\[".*[Ss]ecret.*"\]' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n⚠️  Logging Secrets:"
            rg -n '(Log\.(Debug|Information|Warning|Error)|Console\.WriteLine)\s*\([^)]*\b(password|secret|token|key)\b[^)]*\)' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n📄 Connection Strings:"
            rg -n '"Server=|"Data Source=|"Initial Catalog=|"User Id=|"Password=' \
                --glob '*.json' --glob '*.config' --glob '*.cs' \
                -A 1 -B 1
            ;;
        "csrf-vulnerabilities")
            echo "🔍 Buscando vulnerabilidades CSRF:"
            
            echo -e "\n🚫 ValidateAntiForgeryToken Missing:"
            rg -n '\[HttpPost\](?!.*\[ValidateAntiForgeryToken\])' \
                --glob '*.cs' \
                -A 3 -B 1

            echo -e "\n🔓 CSRF Protection Disabled:"
            rg -n 'IgnoreAntiforgeryToken|ValidateAntiForgeryToken.*false' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🛡️  CSRF Protection (Good):"
            rg -n '\[ValidateAntiForgeryToken\]|services\.AddAntiforgery' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "empty-catches")
            echo "🔍 Buscando bloques catch vacíos:"
            rg -n -U 'catch\s*\([^)]*\)\s*\{\s*(//[^\n]*\n|\s)*\}' \
                --glob '*.cs' \
                -A 2 -B 2
            ;;
        "dependency-pinning")
            echo "🔍 Buscando dependencias sin versión fija:"
            
            echo -e "\n📦 PackageReference sin versión específica:"
            rg -n '<PackageReference.*Version="[^"]*\*[^"]*"|<PackageReference.*Include.*/>(?!.*Version)' \
                --glob '*.csproj' --glob '*.props' \
                -A 1 -B 1

            echo -e "\n🔄 Version Ranges:"
            rg -n 'Version="[\[\(][^"]*[\]\)]"' \
                --glob '*.csproj' --glob '*.props' \
                -A 1 -B 1
            ;;
        "log-injection")
            echo "🔍 Buscando vulnerabilidades de log injection:"
            
            echo -e "\n💉 String Concatenation en Logs:"
            rg -n '(Log\.(Debug|Information|Warning|Error|Critical)|Console\.WriteLine)\s*\([^)]*\+[^)]*\)' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n🔗 String Interpolation en Logs:"
            rg -n '\$"[^"]*\{[^}]+\}[^"]*".*\.(Debug|Information|Warning|Error|Critical)' \
                --glob '*.cs' \
                -A 2 -B 1

            echo -e "\n⚠️  User Input en Logs:"
            rg -n '(Log\.|Console\.WriteLine)\([^)]*\b(request|input|param|user|query)\b[^)]*\)' \
                --glob '*.cs' \
                -A 2 -B 1
            ;;
        "weak-crypto")
            echo "🔍 Buscando algoritmos criptográficos débiles:"
            
            echo -e "\n🔐 Algoritmos Débiles:"
            rg -ni '\b(MD5|SHA1|DES|3DES|RC4|MD4)\b|MD5CryptoServiceProvider|SHA1CryptoServiceProvider' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🎲 Random Débil:"
            rg -n '\bRandom\b|new Random\(\)' \
                --glob '*.cs' \
                -A 1 -B 1

            echo -e "\n🛡️  Crypto Fuerte (Good):"
            rg -n 'RNGCryptoServiceProvider|RandomNumberGenerator|AesCryptoServiceProvider|SHA256|SHA384|SHA512' \
                --glob '*.cs' \
                -A 1 -B 1
            ;;
        "cors-misconfig")
            echo "🔍 Buscando configuraciones peligrosas de CORS:"
            rg -n 'AllowAnyOrigin|WithOrigins\s*\(\s*"\*"|Access-Control-Allow-Origin.*\*' \
                --glob '*.cs' \
                -A 2 -B 1
            ;;
        "all")
            echo "🔍 Ejecutando análisis completo de seguridad C#..."
            for option in endpoints sql-injection command-injection deserialization xss-vulnerabilities authentication-bypass secrets-exposure csrf-vulnerabilities; do
                echo -e "\n" && csharp-find "$option" | head -15
                echo "..."
            done
            ;;
        *)
            echo "🔷 C# Security Analyzer - Opciones disponibles:"
            echo ""
            echo "🌐 Web & API Security:"
            echo -e "\t🛤️  endpoints               - Endpoints HTTP (Controllers, Minimal API, SignalR)"
            echo -e "\t🎭 xss-vulnerabilities     - XSS sinks y output sin encoding"
            echo -e "\t🛡️  authentication-bypass   - Bypasses de autenticación"
            echo -e "\t🌍 csrf-vulnerabilities    - Vulnerabilidades CSRF"
            echo -e "\t🌍 cors-misconfig          - Configuraciones peligrosas de CORS"
            echo ""
            echo "💉 Injection Vulnerabilities:"
            echo -e "\t💾 sql-injection           - SQL injection vulnerabilities"
            echo -e "\t⚡ command-injection        - Command injection vulnerabilities"
            echo -e "\t📁 path-traversal          - Path traversal vulnerabilities"
            echo -e "\t📝 log-injection           - Log injection vulnerabilities"
            echo ""
            echo "🔓 Deserialization & Crypto:"
            echo -e "\t🔄 deserialization         - Deserialización insegura"
            echo -e "\t🔐 weak-crypto             - Algoritmos criptográficos débiles"
            echo ""
            echo "🔐 Information Security:"
            echo -e "\t🔑 secrets-exposure        - Secretos hardcodeados y logging"
            echo -e "\t🕳️  empty-catches           - Bloques catch vacíos"
            echo -e "\t📦 dependency-pinning      - Dependencias sin versión fija"
            echo ""
            echo "🔍 Analysis:"
            echo -e "\t🎯 all                     - Análisis de seguridad completo"
            echo ""
            echo "Ejemplo: csharp-find sql-injection"
            echo "Ejemplo: csharp-find all"
            ;;
    esac
}

python-find() {
    case $1 in
        "endpoints")
            echo "🔍 Buscando endpoints expuestos..."
            echo "--- Flask Routes ---"
            rg -P '\b(app\.route\(|add_url_rule\()\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Flask Application ---"
            rg -P '\bFlask\s*\(__name__\)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Flask Blueprint Routes ---"
            rg -P '@(app|router|bp|blueprint)\.(get|post|put|delete|patch|options|head)\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Django URLs ---"
            rg -P '\b(path|re_path|url)\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Django REST Framework ---"
            rg -P '@(api_view|action)\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- FastAPI Routes ---"
            rg -P '@(app|router)\.(get|post|put|delete|patch|options|head)\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Tornado Handlers ---"
            rg -P '\b(Application\(\s*\[\s*\(|add_handlers\()\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Starlette Routes ---"
            rg -P '\broutes\s*=\s*\[\b' \
                --glob '*.py' --color=always -n -A 3 -B 1
            ;;
            
        "sql-injection")
            echo "🔍 Buscando potenciales vulnerabilidades de SQL Injection..."
            echo "--- Raw SQL Queries ---"
            rg -P '\.(execute|executemany)\(.*%.*\)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- String Formatting in SQL ---"
            rg -P '(SELECT|INSERT|UPDATE|DELETE).*\.(format|%|\+)' \
                --glob '*.py' --color=always -n -A 1 -B 1 -i
            
            echo "--- F-strings with SQL ---"
            rg -P 'f".*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{' \
                --glob '*.py' --color=always -n -A 1 -B 1 -i
            
            echo "--- Raw SQL with format ---"
            rg -P '(cursor|connection)\.(execute|executemany).*\.(format|%)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Django Raw SQL ---"
            rg -P '\b(connection\.execute|cursor\.execute).*%' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "xss")
            echo "🔍 Buscando potenciales vulnerabilidades XSS..."
            echo "--- Unsafe HTML Rendering ---"
            rg -P '\b(render_template_string|Markup|safe|escape=False)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Django Safe Filters Disabled ---"
            rg -P '\b(mark_safe|format_html|safe)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Jinja2 Autoescape Disabled ---"
            rg -P '\bautoescape=False\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Direct HTML Output ---"
            rg -P '\bresponse.*write.*<.*>' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- User Input in Templates ---"
            rg -P 'render.*request\.(GET|POST|args|form)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "rce")
            echo "🔍 Buscando vulnerabilidades de ejecución de código remoto (RCE)..."
            echo "--- Code Execution Functions ---"
            rg -P '\b(eval|exec)\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- OS Command Execution ---"
            rg -P '\b(os\.system|os\.popen|commands\.getoutput)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Subprocess Usage ---"
            rg -P '\bsubprocess\.(Popen|call|run|check_output)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Shell Command Injection ---"
            rg -P '\bsubprocess.*shell=True\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Dynamic Imports ---"
            rg -P '\b(__import__|importlib\.import_module)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Code Compilation ---"
            rg -P '\b(compile|ast\.literal_eval)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- User Input in Dangerous Functions ---"
            rg -P '(eval|exec|os\.system|subprocess).*request\.(GET|POST|args|form|json)' \
                --glob '*.py' --color=always -n -A 3 -B 1
            ;;
            
        "deserialization")
            echo "🔍 Buscando vulnerabilidades de deserialización..."
            echo "--- Pickle Deserialization ---"
            rg -P '\b(pickle\.load|pickle\.loads|cPickle\.load|cPickle\.loads)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- YAML Unsafe Loading ---"
            rg -P '\b(yaml\.load|yaml\.load_all)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Shelve Module ---"
            rg -P '\bshelve\.open\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Dill/Joblib Deserialization ---"
            rg -P '\b(dill\.load|joblib\.load|cloudpickle\.load)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- User Input in Deserialization ---"
            rg -P '(pickle\.load|yaml\.load).*request\.(GET|POST|args|form|files)' \
                --glob '*.py' --color=always -n -A 3 -B 1
            ;;
            
        "file-operations")
            echo "🔍 Buscando operaciones de archivo potencialmente inseguras..."
            echo "--- File Opening ---"
            rg -P '\bopen\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Path Traversal ---"
            rg -P '\bos\.path\.join.*\.\.' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- File Operations with User Input ---"
            rg -P '(open|os\.remove|os\.rename|shutil).*request\.(GET|POST|args|form)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Temporary Files ---"
            rg -P '\btempfile\.(mktemp|NamedTemporaryFile|mkstemp)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Direct Path Usage ---"
            rg -P '\bos\.path\.join.*request\.(GET|POST|args|form)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "xxe")
            echo "🔍 Buscando potenciales vulnerabilidades XXE..."
            echo "--- XML Parsing ---"
            rg -P '\b(xml\.etree\.ElementTree|xml\.dom\.minidom|lxml\.etree)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- XML Parser Configuration ---"
            rg -P '\b(XMLParser|XMLTreeBuilder|XMLParseError)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Unsafe XML Parsing ---"
            rg -P '\bxml\..*parse.*resolve_entities=True\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "ssrf")
            echo "🔍 Buscando potenciales vulnerabilidades SSRF..."
            echo "--- HTTP Requests ---"
            rg -P '\b(requests\.(get|post|put|delete|patch)|urllib\.request\.urlopen)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- URL Opening ---"
            rg -P '\b(urllib\.urlopen|urllib2\.urlopen|httplib)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- User Input in URLs ---"
            rg -P '(requests\.|urllib).*request\.(GET|POST|args|form)' \
                --glob '*.py' --color=always -n -A 3 -B 1
            
            echo "--- Socket Operations ---"
            rg -P '\bsocket\.(socket|connect|bind)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "crypto-issues")
            echo "🔍 Buscando problemas criptográficos..."
            echo "--- Weak Hashing ---"
            rg -P '\b(hashlib\.(md5|sha1)|Crypto\.Hash\.(MD5|SHA1))\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Weak Random ---"
            rg -P '\brandom\.(random|randint|choice)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Hardcoded Keys/Secrets ---"
            rg -P '(secret|key|password|token).*=.*["\'"'"'][A-Za-z0-9+/=]{16,}["\'"'"']' \
                --glob '*.py' --color=always -n -i
            
            echo "--- Weak SSL/TLS ---"
            rg -P '\b(ssl\.PROTOCOL_SSLv|ssl\.PROTOCOL_TLSv1|verify=False)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "auth-bypass")
            echo "🔍 Buscando problemas de autenticación/autorización..."
            echo "--- Debug Mode ---"
            rg -P '\bdebug=True\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Django DEBUG ---"
            rg -P '\bDEBUG\s*=\s*True\b' \
                --glob '*.py' --color=always -n
            
            echo "--- Authentication Decorators ---"
            rg -P '@(login_required|permission_required|user_passes_test)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Session Management ---"
            rg -P '\bsession\.(permanent|modified)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Hardcoded Users/Passwords ---"
            rg -P '(username|user|admin).*=.*(admin|root|test|password)' \
                --glob '*.py' --color=always -n -i
            ;;
            
        "dependency-pinning")
            echo "🔍 Buscando dependency pinning issues..."
            echo "--- Unpinned Dependencies ---"
            rg -P '^[^=]*$|>=|>|~=' --glob 'requirements*.txt' -n
            
            echo "--- Exact Versions ---"
            rg -P '==\d+\.\d+' --glob 'requirements*.txt' -n
            
            echo "--- Poetry Dependencies ---"
            rg -P '\^|\*|>=|>' --glob 'pyproject.toml' -n
            ;;
            
        "empty-catches")
            echo "🔍 Buscando bloques except vacíos..."
            rg -P 'except\s+\w*\s*:\s*(pass|\.\.\.|#.*)?$' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Bare Except ---"
            rg -P 'except\s*:\s*(pass|\.\.\.)' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "console-leaks")
            echo "🔍 Buscando información sensible en logs/consola..."
            echo "--- Print Statements with Exceptions ---"
            rg -P 'print\(.*(Exception|Error|password|secret|key|token).*\)' \
                --glob '*.py' --color=always -n -A 1 -B 1 -i
            
            echo "--- Logging Sensitive Data ---"
            rg -P '(logging\.|logger\.)\w+.*\b(password|secret|key|token|auth|credential)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1 -i
            
            echo "--- Exception Logging ---"
            rg -P '(logging\.|logger\.)(error|warning|exception)\(.*(Exception|Error).*\)' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "log-injection")
            echo "🔍 Buscando potenciales Log Injection..."
            rg -P '(logging\.|logger\.)\w+.*request\.(GET|POST|args|form|json)' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- User Input in Logs ---"
            rg -P 'print.*request\.(GET|POST|args|form)' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "django-security")
            echo "🔍 Buscando problemas de seguridad en Django..."
            echo "--- CSRF Exemption ---"
            rg -P '@csrf_exempt' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Insecure Settings ---"
            rg -P '\b(ALLOWED_HOSTS\s*=\s*\[\s*\*\s*\]|SECRET_KEY\s*=\s*["\'"'"'].*["\'"'"'])\b' \
                --glob '*.py' --color=always -n
            
            echo "--- Raw SQL ---"
            rg -P '\b(connection\.execute|cursor\.execute)\b' \
                --glob '*.py' --color=always -n -A 2 -B 1
            
            echo "--- Django Raw Queries ---"
            rg -P '\b\.raw\(' \
                --glob '*.py' --color=always -n -A 2 -B 1
            ;;
            
        "flask-security")
            echo "🔍 Buscando problemas de seguridad en Flask..."
            echo "--- Debug Mode ---"
            rg -P '\bapp\.run\(.*debug=True.*\)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Secret Key Issues ---"
            rg -P '\bapp\.secret_key\s*=\s*["\'"'"'].*["\'"'"']\b' \
                --glob '*.py' --color=always -n
            
            echo "--- CORS Issues ---"
            rg -P '\bCORS\(.*origins=.*\*.*\)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "risky-libraries")
            echo "🔍 Buscando uso de librerías riesgosas..."
            echo "--- Code Execution ---"
            rg -P '\b(eval|exec|compile)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Serialization ---"
            rg -P '\b(pickle|cPickle|dill|joblib)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- System Operations ---"
            rg -P '\b(os\.system|subprocess|commands)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Network Libraries ---"
            rg -P '\b(urllib|requests|httplib|socket)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- XML Processing ---"
            rg -P '\b(xml\.etree|lxml|BeautifulSoup)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            
            echo "--- Template Engines ---"
            rg -P '\b(jinja2|django\.template|mako)\b' \
                --glob '*.py' --color=always -n -A 1 -B 1
            ;;
            
        "all")
            echo "🚀 Ejecutando análisis completo..."
            for category in endpoints sql-injection xss rce deserialization file-operations xxe ssrf crypto-issues auth-bypass django-security flask-security; do
                echo ""
                echo "==============================================="
                python-find "$category"
                echo "==============================================="
            done
            ;;
            
        *)
            echo "🐍 python-find - Herramienta de análisis estático para Python"
            echo ""
            echo "Categorías disponibles:"
            echo -e "\t📡 endpoints           - Mapeo de endpoints Web"
            echo -e "\t💉 sql-injection       - Potenciales SQL Injection"
            echo -e "\t🔥 xss                 - Potenciales XSS"
            echo -e "\t💥 rce                 - Remote Code Execution"
            echo -e "\t📦 deserialization     - Vulnerabilidades de deserialización"
            echo -e "\t📁 file-operations     - Operaciones de archivo inseguras"
            echo -e "\t📄 xxe                 - XML External Entity"
            echo -e "\t🌐 ssrf                - Server-Side Request Forgery"
            echo -e "\t🔐 crypto-issues       - Problemas criptográficos"
            echo -e "\t🔑 auth-bypass         - Bypass de autenticación"
            echo -e "\t🎯 django-security     - Problemas específicos de Django"
            echo -e "\t🍃 flask-security      - Problemas específicos de Flask"
            echo -e "\t📋 dependency-pinning  - Dependency pinning issues"
            echo -e "\t❌ empty-catches       - Bloques except vacíos"
            echo -e "\t📝 console-leaks       - Info sensible en logs"
            echo -e "\t📜 log-injection       - Log injection"
            echo -e "\t📚 risky-libraries     - Librerías riesgosas"
            echo -e "\t🚀 all                 - Análisis completo"
            echo ""
            echo "Uso: python-find <categoría>"
            echo "Ejemplo: python-find rce"
            ;;
    esac
}

ruby-find() {
    case $1 in
        "endpoints")
            echo "🔍 Buscando endpoints HTTP en Ruby/Rails..."
            
            echo -e "\n🛤️  Rails Routes (config/routes.rb):"
            rg -n '\b(get|post|put|patch|delete|match|root)\s+["\'"'"'][^"'"'"']+["\'"'"']|resources?\s+:[a-zA-Z_]+|namespace\s+:[a-zA-Z_]+' \
                --glob 'config/routes.rb' --glob '**/routes.rb' \
                -A 1 -B 1

            echo -e "\n📋 RESTful Resources:"
            rg -n '\b(resources|resource)\s+:[a-zA-Z_]+' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🎯 Controller Actions:"
            rg -n '^\s*def\s+(index|show|new|create|edit|update|destroy)\b' \
                --glob '**/controllers/**/*.rb' --glob '**/app/controllers/**/*.rb' \
                -A 2 -B 1

            echo -e "\n🌐 Custom Controller Methods:"
            rg -n 'before_action|after_action|around_action' \
                --glob '**/controllers/**/*.rb' --glob '**/app/controllers/**/*.rb' \
                -A 1 -B 1

            echo -e "\n🚀 Sinatra Routes:"
            rg -n '\b(get|post|put|patch|delete|options|head)\s+["\'"'"'/][^"'"'"']*["\'"'"']' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n⚡ Grape API:"
            rg -n '\b(get|post|put|patch|delete|route)\s+["\'"'"'][^"'"'"']+["\'"'"']|resource\s+:[a-zA-Z_]+' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔧 Rack Applications:"
            rg -n 'Rack::Builder|use\s+[A-Z]|map\s+["\'"'"'][^"'"'"']+["\'"'"']' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📍 Route Constraints & Scopes:"
            rg -n '\b(constraints|scope|namespace|mount)\s+' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "sql-injection")
            echo "🔍 Buscando vulnerabilidades de SQL injection:"
            
            echo -e "\n💉 String Interpolation en Queries:"
            rg -n '(where|find_by|find_by_sql|execute|query)\s*\([^)]*#\{[^}]+\}[^)]*\)|"[^"]*#\{[^}]+\}[^"]*".*\.(where|find)' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔗 Concatenación Directa:"
            rg -n '(where|find_by|find_by_sql|execute)\s*\([^)]*\+[^)]*\)' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n⚠️  Raw SQL:"
            rg -n '\b(find_by_sql|execute|connection\.execute|ActiveRecord::Base\.connection\.execute)\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📝 Dynamic Queries:"
            rg -n '\.(where|order|group|having)\s*\([^)]*params\[|\.send\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "command-injection")
            echo "🔍 Buscando vulnerabilidades de command injection:"
            
            echo -e "\n⚡ System Calls con Interpolación:"
            rg -n '(system|exec|spawn|`|\%x)\s*\([^)]*#\{[^}]+\}[^)]*\)|`[^`]*#\{[^}]+\}[^`]*`' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔧 Popen y IO:"
            rg -n '(IO\.popen|Open3\.(popen|capture))\s*\([^)]*#\{[^}]+\}[^)]*\)' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n💻 Kernel Methods:"
            rg -n '\bKernel\.(system|exec|spawn)\s*\([^)]*#\{[^}]+\}[^)]*\)' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🚨 Shell Execution:"
            rg -n '\.system\s*\(|\.exec\s*\(|\.spawn\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "insecure-deserialization")
            echo "🔍 Buscando deserialización insegura:"
            
            echo -e "\n🔓 Marshal (Muy Peligroso):"
            rg -n '\bMarshal\.load\b|\bMarshal\.restore\b' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📄 YAML Load:"
            rg -n '\bYAML\.load\b|\bYAML\.load_file\b' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📊 JSON Parse:"
            rg -n '\bJSON\.load\b|\bJSON\.restore\b' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔒 Safe Alternatives Used:"
            rg -n '\bYAML\.safe_load\b|\bJSON\.parse\b' \
                --glob '*.rb' \
                -A 1 -B 1
            ;;
        "eval-usage")
            echo "🔍 Buscando uso peligroso de eval:"
            
            echo -e "\n⚠️  Eval Directo:"
            rg -n '\beval\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔧 Instance Eval:"
            rg -n '\binstance_eval\s*\(|\bclass_eval\s*\(|\bmodule_eval\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📝 Define Method:"
            rg -n '\bdefine_method\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🚀 Send Method:"
            rg -n '\.send\s*\(|\.public_send\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "file-inclusion")
            echo "🔍 Buscando vulnerabilidades de inclusión de archivos:"
            
            echo -e "\n📂 Require Dinámico:"
            rg -n '\brequire\s*\([^)]*#\{[^}]+\}[^)]*\)|\brequire\s*\([^)]*params\[' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📁 Load Dinámico:"
            rg -n '\bload\s*\([^)]*#\{[^}]+\}[^)]*\)|\bload\s*\([^)]*params\[' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n📋 File Operations:"
            rg -n '\b(File\.read|File\.open|IO\.read)\s*\([^)]*#\{[^}]+\}[^)]*\)' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔄 Path Traversal:"
            rg -n '\.\./|\.\.\\|\bFile\.(join|expand_path)\s*\([^)]*params\[' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "xss-vulnerabilities")
            echo "🔍 Buscando vulnerabilidades XSS:"
            
            echo -e "\n🔓 Raw HTML:"
            rg -n '\.html_safe\b|raw\s*\(' \
                --glob '*.rb' --glob '*.erb' --glob '*.haml' \
                -A 1 -B 1

            echo -e "\n📝 ERB Templates:"
            rg -n '<%=\s*[^%]*params\[|<%=\s*[^%]*@[^%]*%>' \
                --glob '*.erb' \
                -A 1 -B 1

            echo -e "\n🎨 HAML Templates:"
            rg -n '=\s*params\[|=\s*@' \
                --glob '*.haml' \
                -A 1 -B 1

            echo -e "\n🛡️  Sanitize Usage:"
            rg -n '\bsanitize\s*\(|\bstrip_tags\s*\(' \
                --glob '*.rb' \
                -A 1 -B 1
            ;;
        "csrf-bypass")
            echo "🔍 Buscando bypasses de CSRF:"
            
            echo -e "\n🚫 Skip CSRF:"
            rg -n 'skip_before_action\s+:verify_authenticity_token|protect_from_forgery.*false' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔓 Forgery Protection:"
            rg -n 'protect_from_forgery' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "mass-assignment")
            echo "🔍 Buscando vulnerabilidades de mass assignment:"
            
            echo -e "\n📝 Params Permit:"
            rg -n '\.permit\s*\(' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n⚠️  Direct Params Usage:"
            rg -n '\.new\s*\(\s*params\[|\.(create|update)\s*\(\s*params\[' \
                --glob '*.rb' \
                -A 2 -B 1

            echo -e "\n🔒 Strong Parameters:"
            rg -n 'require\s*\([^)]*\)\.permit' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "secrets-exposure")
            echo "🔍 Buscando exposición de secretos:"
            
            echo -e "\n🔑 Hardcoded Secrets:"
            rg -ni '\b(password|secret|key|token|api_key)\s*[=:]\s*["\'"'"'][^"'"'"']{8,}["\'"'"']' \
                --glob '*.rb' --glob '*.yml' --glob '*.yaml' \
                -A 1 -B 1

            echo -e "\n📋 Environment Variables:"
            rg -n 'ENV\s*\[\s*["\'"'"'](SECRET|KEY|PASSWORD|TOKEN)["\'"'"']\s*\]' \
                --glob '*.rb' \
                -A 1 -B 1

            echo -e "\n⚠️  Logging Secrets:"
            rg -n '(logger|Rails\.logger)\.(debug|info)\s*\([^)]*\b(password|secret|token|key)\b[^)]*\)' \
                --glob '*.rb' \
                -A 1 -B 1
            ;;
        "regex-dos")
            echo "🔍 Buscando vulnerabilidades ReDoS:"
            
            echo -e "\n🔄 Regex Complejos:"
            rg -n '\/(.*\*.*\+|.*\+.*\*|\(\?\!|\(\?\=|\(\.\*\)\+|\(\.\*\)\*)\/' \
                --glob '*.rb' \
                -A 1 -B 1

            echo -e "\n⚠️  User Input en Regex:"
            rg -n 'Regexp\.(new|compile)\s*\([^)]*params\[|\/.*#\{[^}]+\}.*\/' \
                --glob '*.rb' \
                -A 2 -B 1
            ;;
        "all")
            echo "🔍 Ejecutando análisis completo de seguridad Ruby..."
            for option in endpoints sql-injection command-injection insecure-deserialization eval-usage xss-vulnerabilities csrf-bypass mass-assignment secrets-exposure; do
                echo -e "\n" && ruby-find "$option" | head -15
                echo "..."
            done
            ;;
        *)
            echo "💎 Ruby Security Analyzer - Opciones disponibles:"
            echo ""
            echo "🌐 Routing & Endpoints:"
            echo -e "\t🛤️  endpoints           - Endpoints HTTP (Rails, Sinatra, Grape)"
            echo ""
            echo "💉 Injection Vulnerabilities:"
            echo -e "\t💾 sql-injection       - SQL injection vulnerabilities"
            echo -e "\t⚡ command-injection    - Command injection vulnerabilities"
            echo -e "\t📁 file-inclusion      - File inclusion vulnerabilities"
            echo ""
            echo "🔓 Deserialization & Execution:"
            echo -e "\t🔄 insecure-deserialization - Marshal, YAML, JSON load"
            echo -e "\t⚠️  eval-usage          - Eval, instance_eval, send usage"
            echo ""
            echo "🌐 Web Security:"
            echo -e "\t🎭 xss-vulnerabilities - XSS sinks and dangerous output"
            echo -e "\t🛡️  csrf-bypass         - CSRF protection bypasses"
            echo -e "\t📝 mass-assignment     - Mass assignment vulnerabilities"
            echo ""
            echo "🔐 Information Security:"
            echo -e "\t🔑 secrets-exposure    - Hardcoded secrets and logging"
            echo -e "\t🔄 regex-dos           - Regular expression DoS (ReDoS)"
            echo ""
            echo "🔍 Analysis:"
            echo -e "\t🎯 all                 - Run comprehensive security scan"
            echo ""
            echo "Ejemplo: ruby-find sql-injection"
            echo "Ejemplo: ruby-find all"
            ;;
    esac
}
