#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>

typedef struct __file_header
{
	unsigned int	iMagic;
	unsigned short	iMaVersion;
	unsigned short	iMiVersion;
	unsigned int	iTimezone;
	unsigned int	iSigFlags;
	unsigned int	iSnapLen;
	unsigned int	iLinkType;

}FILE_HEADER; // pcap 文件头 24字节,仅用了iLinkType，判断链路层是ethenet还是linux cooked

typedef struct
{
	unsigned char  dest_hwaddr[6];
	unsigned char  source_hwaddr[6];
	unsigned short  frame_type; // ipv4 or ipv6

}ETH_HEADER; // 14


typedef struct
{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	// byte 0
	unsigned char  len:4; // header length:单位4字节
	unsigned char  version:4;

	// byte 1
	unsigned char  type_of_service;

	// byte 2-3
	unsigned short  total_len; // 总长度。包括ip头

	// byte 4-5
	unsigned short  frag_flag; // 分片标识，同一片数据标识相同

	// byte 6-7
	unsigned short   frag_offset:13; // 原始数据的开始位置
	unsigned short   lasg_flag:3;  // 1:最后一片
#else

	// byte 0
	unsigned char  version:4;
	unsigned char  len:4; // header length:单位4字节

	// byte 1
	unsigned char  type_of_service;

	// byte 2-3
	unsigned short  total_len; // 总长度

	// byte 4-5
	unsigned short  frag_flag; // 分片标识，同一片数据标识相同

	// byte 6-7
	unsigned short   lasg_flag:3;  // 1:最后一片
	unsigned short   frag_offset:13; // 原始数据的开始位置

#endif

	unsigned char  ttl;
	unsigned char  protocol; // 17:udp,6:tcp
	unsigned short  check_sum;
	unsigned char  src_ip[4];
	unsigned char  dst_ip[4];
	unsigned char options[40];

}IP_HEADER; // 20+options

typedef struct _udp_header
{
	unsigned short src_port;	
	unsigned short dst_port;	
	unsigned short udp_len;	
	unsigned short check_sum;	

}UDP_HEADER;

typedef struct _tcp_header
{
	unsigned short src_port;	
	unsigned short dst_port;	
	unsigned int seq_no;
	unsigned int ack_no;

#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned short flag:6; //  syn? fin? rst?
	unsigned short reserver:6;   //   保留位
	unsigned short header_len:4; // tcp header len 单位4字节
#else

	unsigned short header_len:4; // tcp header len 单位4字节
	unsigned short reserver:6;   //   保留位
	unsigned short flag:6; //  syn or fin or rst ...
#endif

	unsigned short window_size;
	unsigned short check_sum;
	unsigned short emergency_ptr;
	unsigned char options[40];

}TCP_HEADER; //20+options

FILE* fp_src;
IP_HEADER ip_header;
UDP_HEADER udp_header;
TCP_HEADER tcp_header;
int link_type;

int skip_pcap_header()
{
	FILE_HEADER fh;
	fread(&fh, 1, 24, fp_src);
	printf("pcap header:%x\n", fh.iLinkType);
	link_type = fh.iLinkType;

	return 24;
}

int skip_pcap_data_header()
{
	unsigned char buf[16];
	int n = fread(buf, 16, 1, fp_src);
	printf("pcap header:%x,%x,%x,%x:%d\n", buf[0], buf[1], buf[2], buf[3], n);
	return n;
}

int get_eth_header()
{

	if(link_type == 0x71) // linux cook
	{

		unsigned char buf[16];
		int n = fread(buf, 16, 1, fp_src);
		return 16;
	}

	ETH_HEADER eth_header; 
	fread(&(eth_header.dest_hwaddr[0]), 1, 1, fp_src);
	fread(&(eth_header.dest_hwaddr[1]), 1, 1, fp_src);
	fread(&(eth_header.dest_hwaddr[2]), 1, 1, fp_src);
	fread(&(eth_header.dest_hwaddr[3]), 1, 1, fp_src);
	fread(&(eth_header.dest_hwaddr[4]), 1, 1, fp_src);
	fread(&(eth_header.dest_hwaddr[5]), 1, 1, fp_src);

	fread(&(eth_header.source_hwaddr[0]), 1, 1, fp_src);
	fread(&(eth_header.source_hwaddr[1]), 1, 1, fp_src);
	fread(&(eth_header.source_hwaddr[2]), 1, 1, fp_src);
	fread(&(eth_header.source_hwaddr[3]), 1, 1, fp_src);
	fread(&(eth_header.source_hwaddr[4]), 1, 1, fp_src);
	fread(&(eth_header.source_hwaddr[5]), 1, 1, fp_src);

	fread(&(eth_header.frame_type), 2, 1, fp_src);


	printf("dest mac:--------[");
	int i = 0;
	printf("%x", eth_header.dest_hwaddr[0]);
	for(i = 1; i < 6;i++){
		printf(":%x", eth_header.dest_hwaddr[i]);
	}
	printf("]\n");

	printf("src mac:---------[");
	printf("%x", eth_header.source_hwaddr[0]);
	for(i = 1; i < 6;i++){
		printf(":%x", eth_header.source_hwaddr[i]);
	}
	printf("]\n");

	printf("frame type:%d-%x\n", eth_header.frame_type, eth_header.frame_type);
	return 1;
}

int get_ip_header(){

	unsigned char prev8;
	fread(&prev8, 1, 1, fp_src);

	ip_header.version = prev8>>4;
	printf("version:%x--%x--%x\n", ip_header.version, prev8 , (prev8&0x0f)*4);
	ip_header.len = prev8&0x0f;
	printf("ip len:%d\n", (ip_header.len)*4);


	unsigned char buff[ip_header.len*4-1];
	fread(buff, ip_header.len*4-1, 1 ,fp_src);

	int pos = 0;
	memcpy(&ip_header.type_of_service, buff+pos, 1);
	pos++;

	unsigned short _total_len;
	memcpy(&_total_len, buff+pos, 2);
	pos+=2;
	ip_header.total_len = ntohs(_total_len);
	printf("payload len:%d\n", ip_header.total_len);

	int i = 0;
	while(i < 4){  // 暂时没有用到这4个字节

		unsigned char tmp;
		memcpy(&tmp, buff+pos, 1); 
		pos+=1;
		i++;
	}

	memcpy(&ip_header.ttl, buff+pos, 1);
	pos++;
	printf("ttl:%x\n", ip_header.ttl);

	memcpy(&ip_header.protocol, buff+pos, 1);
	pos++;
	printf("protocol :%x\n", ip_header.protocol);

	memcpy(&ip_header.check_sum, buff+pos, 2);
	pos+=2;

	memcpy(&ip_header.src_ip[0], buff+pos, 1 );
	pos++;
	memcpy(&ip_header.src_ip[1], buff+pos, 1 );
	pos++;
	memcpy(&ip_header.src_ip[2], buff+pos, 1 );
	pos++;
	memcpy(&ip_header.src_ip[3], buff+pos, 1 );
	pos++;
	printf("src ip:%d.%d.%d.%d\n", ip_header.src_ip[0], ip_header.src_ip[1], ip_header.src_ip[2], ip_header.src_ip[3]);

	memcpy(&ip_header.dst_ip[0], buff+pos, 1);
	pos++;
	memcpy(&ip_header.dst_ip[1], buff+pos, 1);
	pos++;
	memcpy(&ip_header.dst_ip[2], buff+pos, 1);
	pos++;
	memcpy(&ip_header.dst_ip[3], buff+pos, 1);
	printf("dst ip:%d.%d.%d.%d\n", ip_header.dst_ip[0], ip_header.dst_ip[1], ip_header.dst_ip[2], ip_header.dst_ip[3]);

	return 1;
}

int get_udp_header()
{

	fread(&(udp_header.src_port), 1, 2 ,fp_src);
	printf("src port:%d,%x\n", ntohs(udp_header.src_port), udp_header.src_port);

	fread(&(udp_header.dst_port), 1, 2,fp_src);
	udp_header.dst_port = ntohs(udp_header.dst_port);
	printf("dst port:%d,%x\n", udp_header.dst_port, udp_header.dst_port);

	unsigned short tmplen;
	fread(&(tmplen), 2, 1 ,fp_src);
	udp_header.udp_len = ntohs(tmplen);
	printf("udp total len :%d  and  payload len:%d---tmplen:%d\n", udp_header.udp_len, udp_header.udp_len-8, tmplen);

	fread(&(udp_header.check_sum), 2, 1 ,fp_src);

	return 1;
}

int get_tcp_header()
{

	fread(&(tcp_header.src_port), 2, 1 ,fp_src);
	printf("src port:%d\n", ntohs(tcp_header.src_port));

	fread(&(tcp_header.dst_port), 2, 1 ,fp_src);
	tcp_header.dst_port = ntohs(tcp_header.dst_port);
	printf("dst port:%d\n", tcp_header.dst_port);

	fread(&(tcp_header.seq_no), 4, 1 ,fp_src);
	tcp_header.seq_no = ntohl(tcp_header.seq_no);
	printf("seq_no :%ud\n", tcp_header.seq_no);

	fread(&(tcp_header.ack_no), 4, 1 ,fp_src);
	printf("ack no :%x\n", ntohs(tcp_header.ack_no));

	unsigned short tmp;
	fread(&tmp, 1, 1 ,fp_src);
	printf("tmp:%x\n", (tmp>>4)&0x0f);
	tcp_header.header_len = tmp>>4&0x0f;

	printf("header_len:%d\n", tcp_header.header_len);
	fread(&tmp, 1, 1 ,fp_src);

	//tcp_header.reserver = tmp>>6&0x11f; // unuse
	//tcp_header.flag = tmp&0x11f;        // unuse

	unsigned short tmp1;
	fread(&tmp1, 2, 1 ,fp_src);
	tcp_header.window_size = tmp1;

	fread(&tmp1, 2, 1 ,fp_src);
	tcp_header.check_sum = tmp1;

	fread(&tmp1, 2, 1 ,fp_src);
	tcp_header.emergency_ptr = tmp1;

	if(tcp_header.header_len*4 > 20){
		fread(&(tcp_header.options), tcp_header.header_len*4-20, 1 ,fp_src);
		printf("tcp options len :%d\n",  tcp_header.header_len*4-20);
	}

	return 1;

}

int get_rtp_header()
{
	unsigned char buff[12];	
	fread(buff, 12, 1 ,fp_src);

	return 1;
}

int recv_port= 0;
int remain_data_length = 0; // 还差多少个字节，才能读取出一个完整的tcp包

unsigned char rtp_header[14]; //length(2字节)+rtp header(12字节)

int rtp_header_len = 0;      // 已经读取了rtp header的字节数，有可能因为tcp分片导致，rtp头不在同一个tcp包内

unsigned int next_seq = 0;   // 下一个tcp包的seq 


/*****
 * 国标流如果基于tcp协议，负载的格式是: length(2字节)+rtp header + payload
 ***/
int get_payload_data(FILE* fp_dst)
{

	unsigned char buff[15000];	
	int payload_len = 0;
	if(ip_header.protocol == 6){
		payload_len = ip_header.total_len-20-tcp_header.header_len*4; // ip.total_len-ip header-tcp_header
		printf("tcp payload len:%d\n", payload_len);

	}else if(ip_header.protocol == 17){

		payload_len = udp_header.udp_len-8;
	}

	if(payload_len == 0){
		printf("no payload\n");
		return 0;
	}

	fread(buff, payload_len, 1 ,fp_src);
	printf("data:%x,%x,%x,%x,%x,%x:%d\n", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], remain_data_length);

	if(ip_header.protocol == 17){ // udp

		if(recv_port != udp_header.dst_port) // 不是需要解析的端口
			return 0;

		fwrite(buff+12, payload_len-12, 1, fp_dst);
		fflush(fp_dst);

	}else{ // tcp

		if(next_seq!= 0){

			if( tcp_header.seq_no != next_seq) //tcp乱序，不再执行
			{
				printf("wrong seq, drop frame:%ud,%ud\n",  tcp_header.seq_no, next_seq);
				return -1;

			}
		}
		printf("cur seq:%ud---next seq:%ud\n", tcp_header.seq_no, tcp_header.seq_no+ip_header.total_len-20-tcp_header.header_len*4);
		next_seq = tcp_header.seq_no+ip_header.total_len-20-tcp_header.header_len*4;
		unsigned short rtp_len;

		if(recv_port != tcp_header.dst_port)  // 不是需要解析的端口
			return 0;

		int pos = 0; // 已经处理了的buff中的位置

		while(pos < payload_len){

			if(remain_data_length == 0){ // 上一次已经处理完一个完整的packet, 读取一个新的rtp packet 

				if(rtp_header_len >0 && rtp_header_len<14){ // get a part of rtp header, continue read rtp header from this packet

					memcpy(rtp_header+rtp_header_len, buff+pos, 14-rtp_header_len);
					pos+=(14-rtp_header_len);
					rtp_header_len = 14; // 读到了完整的rtp header

					memcpy(&rtp_len, rtp_header, 2);
					rtp_len = htons(rtp_len); // rtp包的长度(包含rtp header)
					printf("rtp len:%d---rtp_header_len:%d\n", rtp_len, rtp_header_len);

				}else{  


					if(payload_len - pos >= 14){ // payload 中包含完整的rtp header

						memcpy(rtp_header, buff+pos, 14);
						rtp_header_len = 14;
						pos+=14;

						printf("rtp header:%x,%x,%x,%x,%x,%x\n", rtp_header[0], rtp_header[1], rtp_header[2], rtp_header[3], rtp_header[4], rtp_header[5]);

						memcpy(&rtp_len, rtp_header, 2);
						rtp_len = htons(rtp_len);
						printf("rtp len:%d--pos:%d-%x,%x,%x,%x\n", rtp_len, pos, buff[0+pos], buff[1+pos], buff[2+pos], buff[3+pos]);
					}else{ // payload 中rtp head不完整

						memcpy(rtp_header, buff+pos, payload_len-pos);
						rtp_header_len = payload_len-pos;
						pos+=( payload_len-pos);
						printf("no all rtp header:%d-----%x,%x,%x,%x\n", rtp_header_len, rtp_header[0], rtp_header[1], rtp_header[2], rtp_header[3]);
						break;   // get a part of rtp header, continue read rtp header from next packet
					}
				}
				printf("payload_len:%d--pos:%d---rtp_len:%d, %x,%x,%x,%x,%x,%x\n", payload_len, pos, rtp_len, rtp_header[0], rtp_header[1], rtp_header[2], rtp_header[3], rtp_header[4], rtp_header[5]);
				if(payload_len - pos >= rtp_len-12){ // 当前包中可以拼成一个完成的rtp packet

					fwrite(buff+pos, rtp_len-12, 1, fp_dst);
					fflush(fp_dst);
					pos+=(rtp_len-12);
					printf(" write payload_len:%d--pos:%d---rtp_len:%d\n", payload_len, pos, rtp_len);

				}else{ // 当前包中的数据不是一个完整的rtp packet 

					printf("--pos:%d-%x,%x,%x,%x,%x,%x\n", pos, buff[0+pos], buff[1+pos], buff[2+pos], buff[3+pos], buff[4+pos], buff[5+pos]);
					int left_len = 0; // 当前包中还有数据的字节数

					left_len = payload_len-pos;
					printf("rtp len:%d--pos:%d--left len:%d\n", rtp_len, pos, left_len);
					if(left_len > 0){
						fwrite(buff+pos, left_len, 1, fp_dst);
						fflush(fp_dst);
						pos+=(left_len);
					}
					remain_data_length = rtp_len-left_len-12;

				}	

			}else{  // 上一次处理,没有获取到完整的rtp packet 

				if(remain_data_length >=payload_len){

					remain_data_length-=payload_len;
					printf("remain_data_length:%d\n", remain_data_length);
					fwrite(buff+pos, payload_len, 1, fp_dst);
					fflush(fp_dst);
					pos += payload_len;

				}else{

					printf("pos %d , next:%d\n", pos, remain_data_length);
					fwrite(buff+pos, remain_data_length, 1, fp_dst);
					fflush(fp_dst);
					pos+=remain_data_length;
					remain_data_length = 0;
				}
			}

		}

	}

	return 0;
}

int main(int argc, char** argv)
{
	struct stat fs;

	if(lstat(argv[1], &fs) < 0)
	{
		printf("lstat error:%s\n", strerror(errno));
		return -1;
	}

	long filesize = fs.st_size;
	printf("file size is %d\n", filesize);

	FILE* fp_dst = fopen(argv[2], "wb");
	fp_src = fopen(argv[1], "rb");
	recv_port = atoi(argv[3]);
	unsigned int ssrc = 0;

	if(skip_pcap_header() <= 0)
	{

		printf("exit\n");
		fclose(fp_src);
		fclose(fp_dst);
		return 0;
	}
	int count = 1;

	while(1){

		int read_padding = 0;	

		printf("\n\nparse %d frames\n\n", count++);

		if(skip_pcap_data_header() <= 0){
			printf("skip_pcap_data_header break\n");
			break;
		}

		get_eth_header(); 
		get_ip_header();
		if(ip_header.protocol == 17) 		// udp
		{
			if(get_udp_header() <=0){
				printf("get_udp_header break\n");
				break;
			}

			if(get_payload_data(fp_dst) <0 )
				break;

			if(udp_header.dst_port == recv_port){
				read_padding = 1;	
			}

		}else if(ip_header.protocol == 6){  // tcp

			if(get_tcp_header() <= 0)
				break;

			if(get_payload_data(fp_dst) < 0)
				break;

			if(tcp_header.dst_port == recv_port){
				read_padding = 1;	// 需要读取padding
			}
		}

		if(read_padding == 1 && 14/*eth length*/+ip_header.total_len < 60){   // ethnet frame length must >= 60 , or fill padding

			printf("read padding\n");
			char tmp[60] = "";
			if(fread(tmp, 60-14-ip_header.total_len,1, fp_src) < 1) // read padding
				break;	
		}

	}
	printf("end\n");
	fclose(fp_src);
	fclose(fp_dst);
	return 0;
}
