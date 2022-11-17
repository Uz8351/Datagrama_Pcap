# Datagrama_Pcap
/*
------------------------------
|     Dulce bellum inexpertis.|
-------------------------------
|        datagrama.c          |
-------------------------------
|   Hilario Iglesias Martínez | 
-------------------------------
El programa fue realizado
en una plataforma:
LINUX Ubuntu 20.04.4 LTS.
Bajo el standard ANSI-C,
y probado en una consola Linux.
El sistema operativo deberá tener las 
librerías "libpcap" cargadas.

Forma de instalarlas bajo Ubuntu Linux:
--------------------------------------
sudo apt-get update
---------------------------------------------
sudo apt-get install libpcap-dev
------------------------------------------------
**********************************
Este programa una vez compilado
debe ejecutarse bajo administrador
principal ROOT.
************************************
Compilar:
---------

gcc -Wall -Werror -o datagrama   datagrama.c -lpcap

También se adjunta un fichero Makefile
para poder compilar con: make
Al reutilizar make es conveniente borrar
los archivos objeto anteriores.
comando: rm *.o
Ejecutar:
$ sudo ./datagrama

           CAPTURA PAQUETES.
           -----------------
Para agilizar la captura de paquetes,
se puede iciar la navegación por intertet.

Por defecto se ha configurado el puerto 443.
utilizado  para la navegación web segura.
con el protocolo HTTPS.
También podemos probar utilizando
el puerto 80.

El tamaño del PAYLOAD recuperado está
configurado solamente para 128 bytes.
Este valor puede ser variado en la rutina
de volcado, recompilando el programa.
*************************************
*/
