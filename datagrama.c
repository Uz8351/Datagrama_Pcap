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
sudo apt-get install libpcap-dev

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
 
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>
#include <string.h>

void Llamada_Rutina(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
/*
Argumentos de la "Llamada_Rutina":
Esta función es void no tiene valor de retorno
al funcionar en bucle.
Argumentos.
----------
u_char *args:
Es el primer argumento que corresponde al último argumento de pcap_loop (),
con el fin de controlar el bucle repetitivo.
Cualquier valor que se pase como último argumento a pcap_loop ()
se pasa al primer argumento de nuestra función de devolución de 
llamada cada vez que se vuelve allamar a la función.
El segundo argumento es el encabezado pcap,
que contiene información sobre cuándo se detectó
el paquete, qué tamaño tiene, etc.
El formato de esa estructura es el es la sigiente:

struct pcap_pkthdr {
    struct timeval ts;   marca de tiempo 
    bpf_u_int32 caplen;  longitud de la porción presente 
    bpf_u_int32 len;     longitud de este paquete (fuera de línea)


En <sys/time.h> 
Cabecera que define la estructura timeval
incluyendo al menos los siguientes miembros:
time_t         tv_sec      seconds
suseconds_t    tv_usec     microseconds
*/
//------------------------------------------------------
/* Tenemos que localizar un paquete de protocolo IP,
para ello utilizaremos: struct "ether_header"
contenida en: "netinet/if_ether.h", con el siguiente 
formato, con los tipos más importantes que define.

struct  ether_header {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

#define ETHERTYPE_PUP   0x0200       PUP protocol 
#define ETHERTYPE_IP    0x0800       IP protocol 
#define ETHERTYPE_ARP   0x0806       Addr. resolution protocol 

 */

    struct ether_header *Puntero_Cabecera; //eth_header
    Puntero_Cabecera = (struct ether_header *) packet;
    if (ntohs(Puntero_Cabecera->ether_type) != ETHERTYPE_IP) {
     printf("No es un paquete IP \n\n");
        return;
    }

     /*La función "htons ()" convierte el entero
     corto sin signo "hostshort" del orden de
     bytes del host al orden de bytes de la red.
     */

    /* Volver a mirar la struct pcap_pkthdr. 
       ************************************
        La longitud total del paquete, incluidos todos los encabezados.
        y la carga útil de datos se almacena en
        encabezado->len y encabezado->caplen. Caplen es
        la cantidad realmente disponible, y len es la
        longitud total del paquete, incluso si es más grande
        que lo que actualmente hemos capturado. Si la instantánea
        longitud establecida con pcap_open_live() es demasiado pequeña, puede
        no tener todo el paquete. */


    printf("************************************************************************\n");
    printf("Total de paquetes disponibles: %d bytes\n", header->caplen);
    printf("Tamaño del paquete esperado: %d bytes\n", header->len);


    /* Punteros al inicio del encabezado */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Longitud de cabecera en bytes */
    int ethernet_header_length = 14; 

    /*
       ethernet_header_length:
       ----------------------
        Capa de transmisión Ethernet 14 bytes.
        48 bits: Dirección Ethernet de destino
        48 bits: Dirección Ethernet del emisor
        16 bits: Tipo de protocolo = ether_type$ADDRESS_RESOLUTION.
    */
    int ip_header_length;
/*
La longitud mínima de un encabezado IP es de 20
bytes o cinco incrementos de 32 bits.
La longitud máxima de un encabezado IP
es de 24 bytes o seis incrementos de 32 bits.
*/

    int tcp_header_length;
    /*
    El encabezado de tamaño mínimo es de 5 palabras
    y el máximo de 15 palabras, lo que da un tamaño
    mínimo de 20 bytes y un máximo de 60 bytes,
    lo que permite hasta 40 bytes de opciones en el encabezado.
    Este campo recibe su nombre del hecho de que 
    también es el desplazamiento desde el inicio
    del segmento TCP hasta los datos reales.

    */

    int payload_length;


    /*
El tamaño máximo de la carga útil para los paquetes IP
está limitado por el campo Longitud total en el encabezado
del paquete IP; ese campo tiene una longitud de 16 bits,
lo que significa que el valor máximo posible es 216 y el
valor más alto posible para la longitud del paquete es 65.535;
ninguna carga útil puede ser mayor.

    */

    /* Según las dimensiones explicadas anteriormente
    deberemos buscar lo que nos interesa: la cabecera IP.

    Carácteristicas de la "struct ip".
    --------------------------------
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;                header length 
    unsigned int ip_v:4;                 version 
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                 version 
    unsigned int ip_hl:4;                header length 
#endif
    u_int8_t ip_tos;                     type of service 
    u_short ip_len;                      total length 
    u_short ip_id;                       identification 
    u_short ip_off;                      fragment offset field 
#define        IP_RF 0x8000              reserved fragment flag 
#define        IP_DF 0x4000              dont fragment flag 
#define        IP_MF 0x2000              more fragments flag 
#define        IP_OFFMASK 0x1fff         mask for fragmenting bits 
    u_int8_t ip_ttl;                     time to live 
    u_int8_t ip_p;                       protocol 
    u_short ip_sum;                      checksum 
    struct in_addr ip_src, ip_dst;       source and dest address 
  };

               CABECERA DE UN DATAGRAMA IP.
               ---------------------------
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     */        


     
    ip_header = packet + ethernet_header_length;
    /*La segunda mitad del primer byte en ip_header
        contiene la longitud del encabezado IP (IHL). */
    ip_header_length = ((*ip_header) &0x0F);
    /* El IHL es un número de segmento de 32 bits.
     Multiplicar  por cuatro para obtener 
     un recuento de bytes para la aritmética de punteros*/
    ip_header_length = ip_header_length * 4;
    printf("IP longitud de cabecera (IHL) en bytes: %d\n", ip_header_length);

    /* Ahora que sabemos dónde está el encabezado IP, podemos
        inspeccionar el encabezado IP para un número de protocolo para
        asegúrese de que sea TCP antes de continuar.
        El protocolo es siempre el décimo byte del encabezado IP */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("No es un paquete TCP\n\n");
        return;
    }

    /* Agrega la longitud del encabezado ethernet e ip al inicio del paquete
     para encontrar el comienzo del encabezado TCP */

    tcp_header = packet + ethernet_header_length + ip_header_length;

    /* La longitud del encabezado TCP se almacena en la primera mitad
        del byte 12 en el encabezado TCP, porque solo queremos
        el valor de la mitad superior del byte, tenemos que cambiarlo
        hasta la mitad inferior, de lo contrario, está utilizando la mayoría
        bits significativos en lugar de los bits menos significativos */

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    /* La longitud del encabezado TCP almacenada en esos 4 bits representa
        cuántas palabras de 32 bits hay en el encabezado, al igual que
        la longitud del encabezado IP. Volvemos a multiplicar por cuatro para obtener un
        conteo de bytes */

    tcp_header_length = tcp_header_length * 4;
    printf("Tamaño  de la cabecera TCP en bytes: %d\n", tcp_header_length);

    /* Sumamos todos los tamaños de encabezado para encontrar el desplazamiento de la carga útil */

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Tamaño de todas las cabeceras: %d bytes\n", total_headers_size);
    payload_length = header->caplen -(ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Tamaño del PAYLOAD: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Direccion de memoria donde comienza el PAYLOAD: %p\n\n", payload);
    printf("************************************************************************\n");

/*
Con la siguiente rutina pretendemos volcar  el payload configurado a la pantalla.
*/


char Codigo_ascii[17];
int i;
 
for (i = 0; i < 128; ++i) {
        printf("%02X ", ((unsigned char*)payload)[i]);
        if (((unsigned char*)&payload)[i] >= ' ' && ((unsigned char*)payload)[i] <= '~')
         {
            Codigo_ascii[i % 16] = ((unsigned char*)payload)[i];
        } else {
            Codigo_ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1==128) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf(" |  %s \n", Codigo_ascii);
 
}}}

    return ;
}

int main(int argc,char **argv)
{
 
  char *IP; /* notación de punto de la dirección IP de red */
  char *Mascara;/* notación de punto de la dirección de la mascara de red*/
  int Retorno_Look;   /*Retorno del código de la llamada pcap_lookupnet */
  char errbuf[PCAP_ERRBUF_SIZE];/*Bufer para devolver los errores*/
  bpf_u_int32 IP_RAW; /* Valor IP bruta-Kernel */
  bpf_u_int32 Mascara_RAW;/* Mascara de red bruta-kernel */
  struct in_addr Direccion_Addr;/*Asociacion de llamada
   a la struct in_addr*/
  pcap_t* descr;  //Declaramos del descriptor.                              
  pcap_if_t *Dispositivo ;//Declaramos la tarjeta de red.
  struct bpf_program fp; // Apuntamos al programa de filtrado compilado
  char *filtro="tcp and port 443"; //solo el trafico web
  
  
  /* Parámetros para la detección de la 
       tarjeta de red utilizando la
       función:pcap_findalldevs
       ----------------------
pcap_if *   next:
  si no es NULL, un puntero al siguiente
  elemento de la lista;siendo NULL para
  el último elemento de la lista
  ------
char *  name:
un puntero a una cadena
que da un nombre para que el dispositivo pase
de argumento  a pcap_open_live()
  ----------
char *  description:
  si no es NULL, un puntero a una cadena
  que proporciona una descripción legible
  por humanos del dispositivo
  -------------
pcap_addr * addresses:
  un puntero al primer elemento de una
  lista de direcciones para la interfaz
  -------------
u_int   flags:
 Indicadores de interfaz PCAP_IF_. Actualmente,
 el único indicador posible es PCAP_IF_LOOPBACK,
 que se establece si la interfaz es una
 interfaz de bucle invertido.
---------------------
  */
 
  /*
  Estructura Tipo in_addr Direccion_Addr
  -------------------------------------
  situada en: include <netinet/in.h>
  -----------------------------------
  struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
Estructura anidada.
struct in_addr {
    unsigned long s_addr;   abierta con inet_aton()
};
  */
 
  /* Llamamos a la función pcap_findalldevs()
  para elegir el primer dispositivo válido del equipo */
 
 
    if(pcap_findalldevs(&Dispositivo, errbuf) == 0) {
         /* Imprimimos por consola el primer dispositivo de
           red */     
            printf("Dispositivo de red: %s \n", Dispositivo->name);
 
        }
 
    else {
        printf("error: %s\n", errbuf);
        exit(-1);
    }
 
 
  /* Llamada a pcap_lookupnet(), para asociadar el dispositivo o tarjeta
  de red, con la dirección IP y la máscara de red */
  Retorno_Look = pcap_lookupnet(Dispositivo->name,&IP_RAW,&Mascara_RAW,errbuf);
 
  if(Retorno_Look == -1)
  {
   printf("%s\n",errbuf);
   exit(1);
  }
 
  /* Procedemos a optener en formato legible la dirección Ip
  y la máscara de red mediante la función
  "inet_aton()",que convierte la dirección
  de host de Internet de la notación de
  números y puntos IPv4, en forma binaria
  (en orden de bytes de red), y la almacena en la estructura
  a la que apunta un puntero.
  "inet_aton()", devuelve un valor distinto de cero
  si la dirección es válida, cero si no lo es.
  La dirección suministrada en el resultado
  será válida e inteligible en su salida
  por consola.
  */

  Direccion_Addr.s_addr = IP_RAW;
  IP = inet_ntoa(Direccion_Addr);
 
  if(IP == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }
/*imprimimos IP*/

  printf("Dirección IP: %s\n",IP);
 
  /* Hacemos lo mismo  para la máscara de red */
  Direccion_Addr.s_addr = Mascara_RAW;
  Mascara = inet_ntoa(Direccion_Addr);
 
  if(Mascara == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }
  /*Imprimimos máscara de red*/
  printf("Máscara de Red: %s\n",Mascara);

  printf("++ESPERE UNOS INSTANTES++\n");

descr = pcap_open_live(Dispositivo->name,BUFSIZ,1,-1,errbuf); //comenzamos la captura en modo promiscuo
if (pcap_compile(descr,&fp,filtro,0,Mascara_RAW) == -1) //llamamos a "pcap_compile"
{
  fprintf(stderr,"Error compilando el filtro\n");
   exit(1);
}

if (pcap_setfilter(descr,&fp) == -1) //aplicamos el filtro
{
  fprintf(stderr,"Error aplicando el filtro\n");
   exit(1);
}
if (descr == NULL)
{
  printf("pcap_open_live(): %s\n",errbuf);
   exit(1);
   }
pcap_loop(descr,-1,Llamada_Rutina,NULL); //entramos en el bucle infinito
return 0;
}
