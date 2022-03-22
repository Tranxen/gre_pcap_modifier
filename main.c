#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

pcap_hdr_t header;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

pcaprec_hdr_t packet;

unsigned char* g_buffer = NULL;
int g_buffer_size = 0;
int g_buffer_ptr = 0;

static void load_file_into_buffer(char* filename){

  FILE* fd = fopen(filename, "r");
  
  if(!fd){
    printf("file <%s> not found\n", filename);
    exit(-1);
  }

  fseek(fd, 0, SEEK_END);
  g_buffer_size = ftell(fd);
  rewind(fd);
  
  printf("file name : %s\n", filename);
  printf("file size : %d\n", g_buffer_size);
  printf("size of char : %d\n", sizeof(char));
  
  g_buffer = malloc(g_buffer_size);
  
  fread(g_buffer, 1, g_buffer_size, fd);

  printf("%02X %02X %02X %02X\n",
	 g_buffer[g_buffer_size-4],
	 g_buffer[g_buffer_size-3],
	 g_buffer[g_buffer_size-2],
	 g_buffer[g_buffer_size-1]);


  
}

int process_packet_data(unsigned char* buf){

  //look for ethertype (valid would be Ipv4 or 802.1Q)
  unsigned short eth_type = 0;
  unsigned char ip_header_size = 0;
  unsigned char ip_header_protocol = 0;
  unsigned short gre_protocol_type = 0x5865;
  
  int buf_offset = 12; // eth src + eth dst
  int ipv4_offset = 0;
  int gre_offset = 0;
  
  memcpy(&eth_type, buf+buf_offset, sizeof(unsigned short));
  
  //printf("eth_type : %04X\n", eth_type);
  
  buf_offset += 2; // add eth type;

  if(eth_type == 0x0081){ // skip 802.1Q data
    buf_offset += 4;
  }

  // read IPv4 header

  ipv4_offset = buf_offset;

  // read IPv4 header size
  memcpy(&ip_header_size, buf+buf_offset, sizeof(unsigned char));
  ip_header_size = (ip_header_size & 0x0F) * 4;
  //printf("ip header size : %d\n", ip_header_size);

  // skip IPv4 header up to the Protocol part
  buf_offset += 9;

  // read IPv4 header protocol
  memcpy(&ip_header_protocol, buf+buf_offset, sizeof(unsigned char));
  //printf("ip header protocol : %d\n", ip_header_protocol);

  if(ip_header_protocol != 47)
    return 0;
  
  // === rewrite GRE header ===
  gre_offset = ipv4_offset + ip_header_size;
  gre_offset += 2; //skip flag & version header of GRE
  
  memcpy(buf+gre_offset, &gre_protocol_type, sizeof(unsigned short));
  
  return 1;

}

int main(int argc, char** argv){

  FILE* fd;

  int pkt_id = 0;
  int ptr;

  if(argc < 2){
    printf("ERROR : Missing input file\n");
    printf("./gremodifier <pcap_file>\n");
    exit(-1);
  }

  char* fileout = malloc(sizeof(strlen(argv[1]))+5);
  if(!fileout){
    printf("ERROR : fileout char malloc failed\n");
    exit(-1);
  }
  strcpy(fileout, "out_");
  strcat(fileout, argv[1]);
  
  load_file_into_buffer(argv[1]);

  memcpy(&header, g_buffer, sizeof(pcap_hdr_t));
  g_buffer_ptr+=sizeof(pcap_hdr_t);

  printf("magic_number : %4X\n", header.magic_number);
  printf("version : %d.%d\n", header.version_major, header.version_minor);
  printf("this zone : %d\n", header.thiszone);
  printf("sigfigs : %d\n", header.sigfigs);
  printf("snaplen : %d\n", header.snaplen);
  printf("network : %d\n", header.network);
  printf("--\n");

  int ex=0;

  memcpy(&packet, g_buffer+g_buffer_ptr, sizeof(pcaprec_hdr_t));
  g_buffer_ptr+=sizeof(pcaprec_hdr_t);

  while(g_buffer_ptr < g_buffer_size){

    pkt_id++;

    int offset = 0;

    //printf("id : %d\n", pkt_id);
    //printf("ts_sec : %d\n", packet.ts_sec);
    //printf("ts_usec : %d\n", packet.ts_usec);
    //printf("incl_len : %d\n", packet.incl_len);
    //printf("orig_len : %d\n", packet.orig_len);

    offset = packet.incl_len;

    process_packet_data(g_buffer+g_buffer_ptr);
    
    g_buffer_ptr+=offset;

    //printf("--\n");

    //do not copy mem if there is not enough char to copy (sizeof(pcaprec_hdr_t))
    if(g_buffer_ptr < g_buffer_size - sizeof(pcaprec_hdr_t)){
      memcpy(&packet, g_buffer+g_buffer_ptr, sizeof(pcaprec_hdr_t));
      g_buffer_ptr+=sizeof(pcaprec_hdr_t);
    }
    else{
      break;
    }
  
  }

  printf("buffer_ptr : %d\n", g_buffer_ptr);
  printf("buffer_size : %d\n", g_buffer_size);

  FILE* out = fopen(fileout, "w");

  fwrite(g_buffer, 1, g_buffer_size, out);

  fclose(out);

  free(fileout);

  free(g_buffer);
  
  return 0;
  
}
