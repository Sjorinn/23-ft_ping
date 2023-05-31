#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

int loop = 1;

//structure classique d'un packet ping 
struct PingPacket
{
    struct icmphdr hdr;
    char msg[64-sizeof(struct icmphdr)];
};

// Newton Square Root, version simplifiee mais assez precise de la racine carree
double SquareRoot(const double nb)
{
	double	lower;
	double	upper;
	double	sqrt;

	if (nb < 0)
		return (-NAN);
	if (nb == 0)
		return (0.0);
	if (nb < 1) {
		lower = nb;
		upper = 1;
	}
	else {
		lower = 1;
		upper = nb;
	}
	while ((upper - lower) > 0.0001) {
		sqrt = (lower + upper) / 2;
		if (sqrt * sqrt > nb)
			upper = sqrt;
		else
			lower = sqrt;
	}
	return ((lower + upper) / 2);
}

// Termine la boucle
void Handler()
{
    loop = 0;
}

// Check la validite du packet 
unsigned short Checksum(void *Buf, int Len)
{    
    unsigned short *buf = Buf;
    unsigned int    sum = 0;
    unsigned short  result;
 
    for (sum = 0; Len > 1; Len -= 2)
        sum += *buf++;

    if (Len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

char *DnsLookup(char *addr_host, struct sockaddr_in *addr_con)
{
    struct hostent *hostEntity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
 
    if ((hostEntity = gethostbyname(addr_host)) == NULL)
    {
        // Aucune IP trouvee pour l'host
        return NULL;
    }
     
    // On remplis notre structure passee en parametre
    strcpy(ip, inet_ntoa(*(struct in_addr *)hostEntity->h_addr));
    (*addr_con).sin_family = hostEntity->h_addrtype;
    (*addr_con).sin_port = htons (0);
    (*addr_con).sin_addr.s_addr  = *(long*)hostEntity->h_addr;
 
    // On retourne l'ip trouvee pour le hostname
    return ip;
     
}

char* ReverseDnsLookup(char *Ip)
{
    socklen_t len;
    struct sockaddr_in tmp;   
    char buf[NI_MAXHOST];
    char *ret;
 
    tmp.sin_family = AF_INET;
    tmp.sin_addr.s_addr = inet_addr(Ip);
    len = sizeof(struct sockaddr_in);
 
    if (getnameinfo((struct sockaddr *) &tmp, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD))
    {
        // Aucun hostname
        return NULL;
    }
    ret = (char*)malloc((strlen(buf) +1)*sizeof(char));
    strcpy(ret, buf);
    
    // On retourne le hostname de l'ip
    return ret;
}

void SendPing(int Socket, struct sockaddr_in *Address, char *Host, char *Ip, char c)
{
    long unsigned int i;
    int ttl = 64;
    int messageCount = 0;
    int messageReceivedCount = 0;
    int flag = 1;
    unsigned int addressLen;
    
    struct PingPacket packet;
    struct sockaddr_in returnAddress;
    struct timeval totalStart;
    struct timeval start;
    struct timeval totalEnd;
    struct timeval end;

    // temps en millisecondes
    int error = 0;
    long double rtt;
    long double rttMin = 1000;
    long double rttMax = 0;
    double rttMean = 0;
    double rttMdev = 0;
    double rttSquareSum = 0;
    double total;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;

    gettimeofday(&totalStart, NULL);

    // On set le TTL du socket
    if (setsockopt(Socket, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    {
        printf("\nSetting socket options to TTL failed\n");
        return;
    }

    // On set le TO du socket
    setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);

    while (loop)
    {
        flag = 1;

        // On remplit le packet a envoyer 
        bzero(&packet, sizeof(packet));
        packet.hdr.type = ICMP_ECHO;
        packet.hdr.un.echo.id = getpid();
        for (i = 0; i < sizeof(packet.msg)-1; i++)
            packet.msg[i] = i + '0';
        packet.msg[i] = 0;
        packet.hdr.un.echo.sequence = messageCount++;
        packet.hdr.checksum = Checksum(&packet, sizeof(packet));

        //ping toutes les 0.1 sec
        usleep(1000000);

        addressLen=sizeof(returnAddress);

        // On envoie le packet
        gettimeofday(&start, NULL);
        if(loop && sendto(Socket, &packet, sizeof(packet), 0, (struct sockaddr*) Address, sizeof(*Address)) <= 0)
        {
            flag = 0;
        }
        
        if(loop && !(recvfrom(Socket, &packet, sizeof(packet), 0, (struct sockaddr*)&returnAddress, &addressLen) <= 0 && messageCount>1))
        {
            gettimeofday(&end, NULL);
             
            rtt = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec - start.tv_usec) / 1000;
            if (rtt < rttMin)
                rttMin = rtt;
            else if (rtt > rttMax || rttMax == 0)
                rttMax = rtt;
            total += rtt;
            rttSquareSum +=  rtt * rtt;

            messageReceivedCount++;
            // flag si packet bien envoye
            if(loop && flag)
            {
                if(!(packet.hdr.type == 69 && packet.hdr.code == 0))
                {
                    if (messageCount != 1)
                    {
                        printf("From %s (%s) icmp_seq=%d Packet Filtered\n", Host, Ip, messageCount);
                        error++;
                    }
                    messageReceivedCount--;
                }
                else
                {
                    if (!(c >= 48 && c <= 57))
                        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2lf ms.\n", 64, Host, Ip, messageCount, ttl, (double)rtt);
                    else
                    {
                        if (Host == NULL)
                            printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2lf ms.\n", 64, Ip, messageCount, ttl, (double)rtt);
                        else
                            printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2lf ms.\n", 64, Host, messageCount, ttl, (double)rtt);
                    }
                }
            }
        }   
    }
    gettimeofday(&totalEnd, NULL);
    double totalTime = (double)(totalEnd.tv_sec - totalStart.tv_sec) * 1000.0 + (double)(totalEnd.tv_usec - totalStart.tv_usec) / 1000;
    rttMean = total / messageReceivedCount;
    rttMdev = SquareRoot(rttSquareSum / messageReceivedCount - pow(rttMean, 2));
    printf("\n===%s ping statistics===\n", Ip);
    if (messageCount == messageReceivedCount + 1 && (float)(((messageCount - messageReceivedCount)/messageCount) * 100.0) == 0)
    {
        messageCount --;
    }
    if (error > 0)
        printf("%d packets transmitted, %d received, +%d errors, %.2f%% packet loss, time: %.2lf ms.\n", messageCount, messageReceivedCount, error, (float)(((messageCount - messageReceivedCount)/messageCount) * 100.0), totalTime);
    else
        printf("\n%d packets transmitted, %d received, %.2f%% packet loss, time: %.2lf ms.\n", messageCount, messageReceivedCount, (float)(((messageCount - messageReceivedCount)/messageCount) * 100.0), totalTime);
    if (messageReceivedCount != 0)
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", (double)rttMin, (double)rttMean, (double)rttMax, (double)rttMdev);
}

int main(int argc, char *argv[])
{
    int     socketfd;
    char    *ip;
    char    *reverseHostname;
    char    *str;

    // Structure representant l'adresse IP du socket
    struct  sockaddr_in socketAddress;


    if (argc < 2 || argc > 3)
    {
        printf("Usage\n");
        printf("    ./ft_ping [options] <destination>\n\n");
        printf("Options:\n");
        printf("    -v verbose\n");
        printf("    -h help\n");
        return 0;
    }
    else if (argc == 2 && (strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"-v") == 0 || argv[1][0] == '-'))
    {
        printf("Usage\n");
        printf("    ./ft_ping [options] <destination>\n\n");
        printf("Options:\n");
        printf("    -v verbose\n");
        printf("    -h help\n");
        return 0;
    }
    else if (argc == 3 && strcmp(argv[1],"-v") != 0)
    {
        
        printf("Usage\n");
        printf("    ./ft_ping [options] <destination>\n\n");
        printf("Options:\n");
        printf("    -v <destination> verbose\n");
        printf("    -h help\n");
        return 0;
    }
    else if (argc == 3 && strcmp(argv[1], "-v") == 0)
    {
        str = argv[2];
    }
    else
    {
        str = argv[1];
    }
    // On fait un recherche dns en passant le premier parametre et la structure pour la remplir
    ip = DnsLookup(str, &socketAddress);
    
    if (ip == NULL)
    {
        printf("ft_ping: %s: Name or service not known\n", str);
        return 0;
    }

    // On fait un reverse dn si on nous passe un nom de domaine et non une ip
    reverseHostname = ReverseDnsLookup(ip);
    printf("FT_PING %s (%s) 56(84) bytes of data.\n", str, ip);

    // On ouvre un socket
    socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd < 0)
    {
        printf("\nFailed to open socket: Descriptor not received.\n");
        return 0;
    }

    // On catch le ctrl+c
    signal(SIGINT, Handler);

    // boucle de ping
    SendPing(socketfd, &socketAddress, reverseHostname, ip, str[0]);
    
    return 0;
}