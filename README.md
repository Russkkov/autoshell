# AutoSHELL

AutoSHELL es un script para generar una reverse shell, bind reverse shell o meterpreter shell de forma automática siguiendo paso a paso el menú e indicándole la IP y el puerto a utilizar (ver Uso 1).

También puede generarse la reverse shell usando los parámetros (ver Uso 2).

En la forma de uso 1 y 2 se mostrará el código de la shell en el lenguaje indicado así como codificado en base64 y url.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

# Instalación

git clone https://github.com/Russkkov/autoshell.git

cd autoshell

chmod +x autoshell.sh

cp autoshell.sh /usr/bin

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

# Uso

**- Uso 1: autoshell.sh**

```
autoshell.sh
```
 Si se ejecuta el script sin parámetros se abrirá el menú con los tipos de reverse shell disponibles y te guiará paso por paso.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**- Uso 2: autoshell.sh [-t] {tipo} [-i] {IP} [-p] {puerto} [-r][-b][-v]**
  
 ```
 p.e.: autoshell.sh -t bash -i 127.0.0.1 -p 8080 -r
 ```
 
El tipo de reverse shell se indica con el parámetro -t seguido del nombre (-t bash). Para conocer los tipos de reverse shell disponibles ver Uso 3.

La IP se indica con el parámetro -i seguido de la IP local (-i 127.0.0.0).

El puerto se indica con el parámetro -p seguido del número de puerto a utilizar (-p 8080).

El modo de shell (reverse, bind o MSFVenom) se indica con -r, -b o -v. Para conocer los tipos de shell disponibles ver Uso 5.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**- Uso 3: autoshell.sh [-e] {puerto}**

```
p.e.: autoshell.sh -e 8080
```

Si se usa el parámetro -e seguido del número de puerto se mostrarán las distintas formas de poner en escucha un puerto.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**- Uso 4: autoshell.sh [-l][--list][--lista]**

```
autoshell.sh -l
```

Si se usa el parémtro -l, --list o --lista se mostrarán todos los tipos de reverse shell disponibles y su nombre a usar en el argumento [-t] para cada tipo de modo de los parámetros [-r], [-b] o [-v].

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

 **- Uso 5: autoshell.sh [-m][--mod][--modo]**
 
 ```
 autoshell.sh -m
 ```
	
Si se usa el parémtro -m, --mod o --modo se mostrarán los modos de reverse shell posibles.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**- Uso 6: autoshell.sh [-c][--code][--codigo] {nombre_tipo}**

```
autoshell.sh -c
```

Si se usa el parémtro -c, --code o --codigo seguido del nombre del tipo de reverse shell se mostrará un código de ejemplo para el tipo indicado.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**- Uso 7: autoshell.sh [-h][--help][--ayuda]**

```
autoshell.sh -h
```

Si se usa el parémtro -h, --help o --ayuda se mostrará este panel de ayuda.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

 # Tipos
 
 ```
 autoshell.sh -l
 ```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

**Tipos de reverse shell incluidos:**

- Awk
- Bash
- C
- Dart
- Gawk
- Golang
- Java
- Javascript
- Lua
- Nc
- Ncat
- Node.js
- Perl
- PHP
- PowerShell
- Python
- Regsvr32
- Ruby
- Rustcat
- Socat 
- Telnet
- Zsh

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

 **Tipos de bind reverse shell incluidos:**
 
- Python

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

 **Tipos de MSFVenom reverse shell incluidos:**
 
- Android
- Bash
- JSP
- Linux
- macOS
- PHP
- WAR
- Windows

