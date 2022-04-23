# AutoSHELL

AutoSHELL es un script para generar una reverse shell, bind reverse shell o MSFVenom reverse shell de forma automática siguiendo paso a paso el menú e indicándole la IP y el puerto a utilizar (ver Uso 1).
También puede generarse la reverse shell usando los parámetros (ver Uso 2).

**- Uso 1: autoshell.sh**

```
autoshell.sh
```
 
 Si se ejecuta el script sin parámetros se abrirá el menú con los tipos de reverse shell disponibles y te guiará paso por paso.

**- Uso 2: autoshell.sh [-t] {tipo} [-i] {IP} [-p] {puerto} [-r][-b][-v]**
 
 
 ```
 p.e.: autoshell.sh -t bash -i 127.0.0.1 -p 8080 -r
 ```
 
 El tipo de reverse shell se indica con el parámetro -t seguido del nombre (-t bash). Para conocer los tipos de reverse shell disponibles ver Uso 3.
	La IP se indica con el parámetro -i seguido de la IP local (-i 127.0.0.0).
	El puerto se indica con el parámetro -p seguido del número de puerto a utilizar (-p 8080).
	El modo de shell (reverse, bind o MSFVenom) se indica con -r, -b o -v. Para conocer los tipos de shell disponibles ver Uso 5.

**- Uso 3: autoshell.sh [-e] {puerto}**

```
p.e.: autoshell.sh -e 8080
```

 Si se usa el parámetro -e seguido del número de puerto se mostrarán las distintas formas de poner en escucha un puerto.

**- Uso 4: autoshell.sh [-l][--list][--lista]**

```
autoshell.sh -l
```

 Si se usa el parémtro -l, --list o --lista se mostrarán todos los tipos de reverse shell disponibles y su nombre a usar en el argumento [-t] para cada tipo de modo de los parámetros [-r], [-b] o [-v].

 **- Uso 5: autoshell.sh [-m][--mod][--modo]**
 
 ```
 autoshell.sh -m
 ```
	
 Si se usa el parémtro -m, --mod o --modo se mostrarán los modos de reverse shell posibles.

**- Uso 6: autoshell.sh [-i][--info] {nombre_tipo}**

```
autoshell.sh -i
```

 Si se usa el parémtro -i o --info seguido del nombre del tipo de reverse shell se mostrará un código de ejemplo para el tipo indicado.

**- Uso 7: autoshell.sh [-h][--help][--ayuda]**

```
autoshell.sh -h
```

 Si se usa el parémtro -h, --help o --ayuda se mostrará este panel de ayuda.


 # Tipos
 
 ```
 autoshell.sh -l
 ```

**Tipos de reverse shell incluidos:**

- Awk
- Bash
- C
- C#
- Dart
- Golang
- Groovy
- Haskell
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
- Ruby
- Rustcat
- Socat 
- Telnet
- Windows conpty
- Zsh


 **Tipos de bind reverse shell incluidos:**
 
- PHP
- Python

 
 **Tipos de MSFVenom reverse shell incluidos:**
 
- Android
- Bash
- JSP
- Linux
- macOS
- PHP
- Python
- WAR
- Windows

