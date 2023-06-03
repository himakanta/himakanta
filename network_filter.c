typedef struct 
{ 
    uint8_t   version;   /* Header version and length (dwords). */
    uint8_t   header_len; /* Header version and length (dwords). */
    uint8_t   tos;    /* Service type. */
    uint16_t  total_len;     /* Length of datagram (bytes). */
    uint16_t  id;      /* Unique packet identification. */
    uint8_t   flags; 
    uint16_t  fragment_offset;   /* Flags; Fragment offset. */
    uint8_t   ttl; /* Packet time to live (in network). */
    uint8_t   protocol;   /* Upper level protocol (UDP, TCP). */
    uint16_t  checksum;   /* IP header checksum. */
    uint32_t  src_addr;   /* Source IP address. */
    uint32_t  dest_addr;  /* Destination IP address. */
    uint8_t*  option;
    uint8_t   option_len;
    uint8_t*  data;
    uint32_t  data_len;

} NetIpHdr; 

/* This API will decode the IP packet coming from the network */
NetIpHdr Decode_Ip_Packet(char *data, uint32_t pktlen)
{
    NetIpHdr ip;
    ip.version = data[0] & 0xf0) >> 4;
    ip.header_len = data[0] & 0x0f;
    ip.tos = data[1];
    ip.total_len = ntos(*(uint16_t*) data+2);
    ip.id = ntos(*(uint16_t*) data+4);
    ip.flags = (data[6] & 0xe0) >> 5;
    ip.fragment_offset = ntos(*(uint16_t*) data+6) & 0x1f;
    ip.ttl = data[8];
    ip.protocol = data[9];
    ip.checksum = ntos(*(uint16_t*) data+10);
    inet_ntohs(AF_INET, data+12, ip.src_addr, 32);
    inet_ntohs(AF_INET, data+16, ip.dst_addr, 32);

    
    /* If the header len is greater than 5:
       then the remaning header data will get conderd as option data 
     */
    if(ip.header_len > 5)
    {
        ip.option = data+20;
        ip.option_len = (ip.header_len - 5) * 4;
        ip.option = malloc((ip.option_len)+1);
        if(ip.option)
        {
            memset(ip.option, 0, (ip.option_len*4)+1)
            memcpy(ip.option, data+20, (ip.option_len*4));
        }
    }
    else
    {
        ip.option = NULL;
        ip.option_len = 0;
    }
    
    /* The actual payload will be after the header and option */
    ip.data = malloc(pktlen - 20 - ip.option_len);
    if(ip.data)
    {
        ip.data_len = pktlen - 20 - ip.option_len;
        memcpy(ip.data, data+20+ip.option_len, pktlen - 20 - ip.option_len);
    }
    
    return ip;
    
    /* Note: The Free will get called once the caller of the API get the data 
       then free the memory */
}

struct ipv6_packet {
    uint8_t version;
    uint8_t nxthdr;
    int16_t plen;
    char src_addr[128];
    char dst_addr[128];
    uint8_t protocol;
    char *data;
}

struct ipv6_packet Decode_Ipv6_Packet(char *data)
{
    struct ipv6_packet packet;
    packet.version = (data[0] & 0xf0) >> 4;
    packet.nxthdr = data[6];
    packet.plen = ntohs(*int16_t*)(data+4));
    inet_ntop(AF_INET6, data+8, packet.src_addr, 128);
    inet_ntop(AF_INET6, data+8, packet.dst_addr, 128);
    packet.protocol = data[6];
    packet.data = (char *)(data+40);
    return packet;
}

Print_Packet_Tcpdump(uint32_t pktlen, struct time_t timestamp, char *data)
{
    if(!data)
        return;
    
    uint16_t SrcPort;
    uint16_t DrcPort;

    if(data[12] == 0x08 && data[13] == 0x00)
    {
        NetIpHdr ip = Decode_Ip_Packet(data[14], pktlen-14)
        /* After the IP header the remaining data will be the start of TCP header */
        char* tcp_data = ip.data;
        uint32_t tcp_packetlen = ip.data_len;

        if(tcp_packetlen >= 2)
        {
            /* The First two byte of the data will be the TCP header */
            SrcPort = tcp_data[0] >> 8 |tcp_data[1] << 8;
            tcp_packetlen = tcp_packetlen-2;
            if(tcp_packetlen >= 2)
            {
                DstPort = tcp_data[2] >> 8 |tcp_data[3] << 8;
                
                ParseDataRegex(tcp_data+4, SrcPort, DrcPort);
            }
            else
            {
                DstPort = 0;
            }
        }
        else
        {
            SrcPort = 0;
        }
    }

    if(data[12] == 0x86 && data[13] == 0xdd)
    {
        NetIpv6Hdr ipv6 = Decode_Ipv6_Packet(data[14], pktlen-14)
        char* tcp_data = ipv6.data;
        uint32_t tcp_packetlen = ipv6.data_len;

        if(tcp_packetlen >= 2)
        {
            SrcPort = tcp_data[0] >> 8 |tcp_data[1] << 8;
            tcp_packetlen = tcp_packetlen-2;
            if(tcp_packetlen >= 2)
            {
                DstPort = tcp_data[2] >> 8 |tcp_data[3] << 8;
                
                ParseDataRegex(tcp_data+4, SrcPort, DrcPort);
            }
            else
            {
                DstPort = 0;
            }
        }
        else
        {
            SrcPort = 0;
        }
    }
}