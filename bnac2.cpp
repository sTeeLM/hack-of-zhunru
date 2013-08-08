#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <string.h>
#include <sstream>
#include <string>

#include "packet.h"
#include "enc.h"

#ifndef WIN32
#define INVALID_SOCKET -1
typedef int SOCKET;
#else
#define MSG_NOSIGNAL 0
typedef int socklen_t;
#endif

#define BNAC__VERSION__ "1.0.0.5"
#define BNAC_PORT 10001  // tcp and udp
#define BNAC_SERVER "172.22.1.144"
#define BNAC_PIDFILE "/var/run/bnac.pid"
#define BNAC_PING_SERVER "www.baidu.com"
#define BNAC_PING_PORT 80
#define BNAC_CLIENTID "{92E60DFA-3C36-46D7-91C3-668B9AE32C0A}"


#define BNAC_ERR_OK 0
#define BNAC_ERR_INVALID_PARAM 1
#define BNAC_ERR_AUTH_FAIL 2
#define BNAC_ERR_SYSTEM    3

static int g_quiet;
static int g_nodaemon = 1;

static struct option long_options[] = {
                   {"server", 1, 0, 'S'},
                   {"port", 1, 0, 'P'},
                   {"user", 1, 0, 'u'},
                   {"password", 1, 0, 'p'},
                   {"version", 0, 0, 'v'},
                   {"help", 0, 0, 'h'},
                   {"quiet", 0, 0, 'q'},
#ifndef WIN32
                   {"pidfile", 1, 0, 'f'},
                   {"daemon", 0, 0, 'D'},
#endif
                   {"cientid", 1, 0, 'c'},
                   {0, 0, 0, 0}
};


static void shout(const char * fmt, ...)
{
	char buffer[1024];
	va_list ap;
	if(! g_quiet) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);

		fflush(stdout);
	}
}

static void socket_error(const std::string & fun)
{
	char buffer[1024];
#ifdef WIN32
	int err = WSAGetLastError();
		FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		0,
		buffer,
		sizeof(buffer),
		NULL);
#else
	snprintf(buffer, sizeof(buffer), "%s errno: %s\n", fun.c_str(), strerror(errno));
#endif
	shout(buffer);
}

#ifdef WIN32
static char* inet_ntop(int af, const void* src, char * dst, int cnt){

	struct sockaddr_in srcaddr;

	memset(&srcaddr, 0, sizeof(struct sockaddr_in));
	memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

	srcaddr.sin_family = af;
	if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, (LPDWORD) &cnt) != 0) {
		socket_error("inet_ntop:");
		return NULL;
	}
	return dst;
}
#endif

static void show_version()
{
	shout("BNAC2 mac hack version %s, by sTeeL<steel.mental@gmail.com>\n", BNAC__VERSION__);
}

static void show_usage(const std::string & prog)
{
	show_version();
#ifdef WIN32
	shout("Usage: %s -u user -p pass [-q] [-s server] [-P port] [-c clientid]\n", prog.c_str());
#else
	shout("Usage: %s -u user -p pass [-q] [-s server] [-P port] [-D] [-f pidfile] [-c clientid]\n", prog.c_str());
#endif
	shout("Options: -s --server <bnac server>: set bnac server, default %s\n", BNAC_SERVER);
	shout("         -P --port <bnac port>    : set bnac port, default %d\n", BNAC_PORT);
	shout("         -u --user <user>         : set domain user\n");
	shout("         -p --password <password> : set domain password\n");
	shout("         -q --quiet               : show nothing\n");
#ifndef WIN32
	shout("         -f --pidfile <pidfile>   : set location of pid file, default %s\n", BNAC_PIDFILE);
	shout("         -D --daemon              : run as daemon\n", BNAC_PIDFILE);
#endif
	shout("         -c --clientid <clientid> : set client id, default %s\n", BNAC_CLIENTID);
	shout("         -v --version             : show version\n");
	shout("         -h --help                : show this screen\n");
}

static std::string rsa_enc_pass(const std::string & password)
{
	return std::string("");
}

bool init_socket()
{
#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD( 2, 0 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return false;
	}

	shout("%s ", wsaData.szDescription);
	shout("%s ready\n",wsaData.szSystemStatus);

	if ( LOBYTE( wsaData.wVersion ) != 2 ||
			HIBYTE( wsaData.wVersion ) != 0 ) {
		WSACleanup( );
		return false;
	}

	return true;
#else
	return true;
#endif
}

void close_socket(SOCKET sock)
{
#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}

SOCKET make_connection(const std::string & server, uint16_t port)
{
	SOCKET sock = INVALID_SOCKET;
	struct sockaddr_in server_addr;
	struct hostent * hostp = NULL;
	int namelen = sizeof(server_addr);

	hostp = gethostbyname(server.c_str());
	if(!hostp) {
		socket_error("gethostbyname:");
		goto err;
	}

	// make socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(INVALID_SOCKET == sock) {
		goto err;
	}

	// connect to server
	namelen =  sizeof(server_addr);
	memset(&server_addr, 0, namelen);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	memcpy(&server_addr.sin_addr, hostp->h_addr, sizeof(server_addr.sin_addr));
	shout("try to connection %s(%s) %u...", server.c_str(), inet_ntoa(server_addr.sin_addr), port);

	if(connect(sock, (const struct sockaddr*)&server_addr, namelen) <0 ) {
		socket_error("connect:");
		goto err;
	}
	shout("OK, sock is %d\n", sock);
	return sock;
err:
	if(sock != INVALID_SOCKET) {
		close_socket(sock);
		sock = INVALID_SOCKET;
	}
	return sock;
}

static bool read_raw_data(SOCKET sock, void * buffer, size_t len)
{
	char * cbuffer = (char *)buffer;
	size_t readed = 0;
	int ret;

	if(len == 0 || buffer == NULL)
		return false;

	while(len > 0) {
		ret = recv(sock, cbuffer + readed, len, 0);
		if(ret > 0) {
			readed += ret;
			len -= ret;
		} else {
			socket_error("recv:");
			return false;
		}
	}
	return true;
}

static bool send_raw_data(SOCKET sock, void * buffer, size_t len)
{
	char * cbuffer = (char *)buffer;
	size_t sended = 0;
	int ret;

	if(len == 0 || buffer == NULL)
		return false;

	while(len > 0) {
		ret = send(sock, cbuffer + sended, len, MSG_NOSIGNAL);
		if(ret > 0) {
			sended += ret;
			len -= ret;
		} else {
			socket_error("send:");
			return false;
		}
	}

	return true;
}

static bool read_plain_packet(SOCKET sock, packet_t & packet)
{
	int len = 0;
	char buffer[4096];
	char b;
	bool ret;
	
	memset(buffer, 0, sizeof(buffer));
	while(len < sizeof(buffer)) {
		ret = read_raw_data(sock, &b, 1);
		if(ret) {
			buffer[len++] = b;
			if(len >=4 &&
				buffer[len-4] == '\r' &&
				buffer[len-3] == '\n' &&
				buffer[len-2] == '\r' &&
				buffer[len-1] == '\n' ) {
				buffer[len] = 0;
				shout("[TRY READ PLAIN PACKET]\n%s", buffer);
				break;
			}
		} else {
			return false;
		}
	}

	if(len == 0)
		return false;

	return packet.from_buffer(buffer, len);
}

static bool send_plain_packet(SOCKET sock, const packet_t & packet)
{
	char buffer[4096];
	size_t len;
	bool ret;

	memset(buffer, 0, sizeof(buffer));

	if((len = packet.to_buffer(buffer, sizeof(buffer))) == 0)
		return false;

	shout("[TRY SEND PLAIN PACKET]\n%s", buffer);

	ret = send_raw_data(sock, buffer, len);
	
	return ret;
}

static bool read_enc_packet(SOCKET sock, packet_t & packet, int cipher_num)
{
	uint32_t real_len = 0;
	uint32_t packet_len = 0;
	uint32_t n, r;
	char buffer[4096];
	bool ret;

	memset(buffer, 0, sizeof(buffer));

	if(!read_raw_data(sock, &real_len, sizeof(real_len)))
		return false;

	if(real_len == 0)
		return false;

	n = real_len / 16;
	r = real_len % 16;

	if(r != 0) {
		packet_len = (n+1)*16;
	} else {
		packet_len = n*16;
	}

	if(packet_len > sizeof(buffer))
		return false;

	if(!read_raw_data(sock, &buffer, packet_len))
		return false;

	if(!dec_buffer(buffer, real_len, packet_len, cipher_num))
		return false;

	buffer[real_len] = 0;
	
	shout("[TRY READ ENC PACKET]\n%s", buffer);

	return packet.from_buffer(buffer, real_len);

}

static bool send_enc_packet(SOCKET sock, const packet_t & packet, int cipher_num)
{
	uint32_t real_len = 0;
	uint32_t packet_len = 0;
	uint32_t n, r;
	char buffer[4096];

	// 这里还是一个bug，如果分两次调用send，先发送4字节长度包再发送数据包，远程直接关连结
	// 我们走的是TCP不是UDP，TCP是流式的bnac的同学们，这种低级bug很让人无语

	memset(buffer, 0, sizeof(buffer));
	real_len = packet.to_buffer(buffer + sizeof(real_len), sizeof(buffer) - sizeof(real_len));

	if(real_len == 0)
		return false;

	memcpy(buffer, &real_len, sizeof(real_len));

	shout("[TRY SEND ENC PACKET]\n%s", buffer + sizeof(uint32_t));

	n = real_len / 16;
	r = real_len % 16;

	if(r != 0) {
		packet_len = (n+1)*16;
	} else {
		packet_len = n*16;
	}

	if(packet_len + sizeof(real_len)> sizeof(buffer))
		return false;

	if(!enc_buffer(buffer + sizeof(real_len), real_len, packet_len, cipher_num))
		return false;

	return send_raw_data(sock, buffer, packet_len + sizeof(real_len));
}

static bool fill_time_str(SOCKET sock, std::string & buffer, const std::string & session_id)
{
    struct sockaddr_in name;
    char sock_name[256];
    char time_str[256];
    char md5[MD5_DIGEST_LENGTH];
    socklen_t sock_len = sizeof(name);
    int i;

    if(getsockname(sock, (struct sockaddr *)&name, &sock_len) < 0) {
        socket_error("getsockname:");
        return false;
    }

    memset(sock_name, 0, sizeof(sock_name));
    if(inet_ntop(AF_INET, &name, sock_name, sock_len) == NULL) {
        return false;
    }

    sprintf(time_str, "%s:%s:%s", "liuyan", session_id.c_str(), sock_name);

    /* md5 it into g_szTime */
    if(MD5((const unsigned char*)time_str, strlen(time_str), (unsigned char*)md5) == NULL) {
        return false;
    }

    packet_t::append_str(buffer, md5, MD5_DIGEST_LENGTH);

    return true;
}

static bool auth(const std::string client_id, const std::string & user, const std::string & password, 
	const std::string & server, uint16_t port, std::string & session_id, int & cipher_num, bool & auth_fail)
{
	packet_t packet;
	SOCKET auth_sock = INVALID_SOCKET;
	std::string enc_pass = "";
	std::string role = "";
	std::string time_str = "";
	bool ret = false;

	auth_fail = false;
	cipher_num = 0;


	// enc password
	if(!rsa_enc_pass(password, enc_pass)) {
		goto err;
	}

	// make connection
	if((auth_sock = make_connection(server, port)) == INVALID_SOCKET) {
		goto err;
	}
	
	////////////////////////////////////////////hand shake, cipher num///////////////////////////////////////////
	// send in plain
	//ASK_ENCODE
	//PLATFORM:MAC
	//VERSION:1.0.1.22
	//CLIENTID:{92E60DFA-3C36-46D7-91C3-668B9AE32C0A}
	
	packet.clear();
	packet.set_header("ASK_ENCODE");
	packet.set_option("PLATFORM", "MAC");
	packet.set_option("VERSION", "1.0.1.22");
	packet.set_option("CLIENTID", client_id.c_str());

	if(!send_plain_packet(auth_sock, packet)) {
		goto err;
	}

	// read in plain
	//601
	//CIPHERNUM:1

	if(!read_plain_packet(auth_sock, packet)) {
		goto err;
	}

	if(strcmp(packet.get_header().c_str(), "601") || !packet.option_exist("CIPHERNUM")) {
		goto err;
	}

	cipher_num = atoi(packet.get_option("CIPHERNUM").c_str());
	if(cipher_num <= 0 || cipher_num > 10) {
		goto err;
	}

	///////////////////////////////////////////////////// sesame phase 1///////////////////////////////////
	// send in enc
	//OPEN_SESAME
	//SESAME_MD5:INVALID MD5
	packet.clear();
	packet.set_header("OPEN_SESAME");
	packet.set_option("SESAME_MD5", "INVALID MD5");
	if(!send_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}

	// read in enc
	//603
	//INDEX:1
	if(!read_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	
	if(strcmp(packet.get_header().c_str(), "603") || !packet.option_exist("INDEX")) {
		goto err;
	}
	/////////////////////////////////////////////////////sesame phase 2////////////////////////////////////
	// send in enc
	//SESAME_VALUE
	//VALUE:0
	packet.clear();
	packet.set_header("SESAME_VALUE");
	packet.set_option("VALUE", "0");
	if(!send_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	
	// read in enc
	//604
	//RESULT:TRUE
	if(!read_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	if(strcmp(packet.get_header().c_str(), "604") || !packet.option_exist("RESULT")
		|| strcmp(packet.get_option("RESULT").c_str(), "TRUE")) {
		goto err;
	}
	//////////////////////////////////////////////////////auth///////////////////////////////////////////
	// send in enc
	//AUTH
	//OS:MAC
	//USER:xxx
	//PASS:xxx
	//AUTH_TYPE:DOMAIN

	packet.clear();
	packet.set_header("AUTH");
	packet.set_option("OS", "MAC");
	packet.set_option("USER", user.c_str());
	packet.set_option("PASS", enc_pass.c_str());
	packet.set_option("AUTH_TYPE", "DOMAIN");
	if(!send_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	// read in enc
	//288
	//SESSION_ID:13756963409705689
	//ROLE:1
	if(!read_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	if(strcmp(packet.get_header().c_str(), "288") || !packet.option_exist("SESSION_ID") || !packet.option_exist("ROLE")) {
		auth_fail = true;
		goto err;
	}

	session_id = packet.get_option("SESSION_ID");
	role = packet.get_option("ROLE");

	//////////////////////////////////////////////////////push role///////////////////////////////////////////
	// send in enc
	//PUSH
	//TIME:D?\034??T?\026x/\a\025rt?, //又一个bug，你们直接把MD5放里面，不转码下么？
	//SESSIONID:13756963409705689
	//ROLE:1
	if(!fill_time_str(auth_sock, time_str, session_id)) {
		goto err;
	}
	packet.clear();
	packet.set_header("PUSH");
	packet.set_option("TIME", time_str);
	packet.set_option("SESSIONID", session_id.c_str());
	packet.set_option("ROLE", role.c_str());
	if(!send_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	// read in enc
	//220
	//DETAILS:ACCESS GRANTED
	if(!read_enc_packet(auth_sock, packet, cipher_num)) {
		goto err;
	}
	if(strcmp(packet.get_header().c_str(), "220") || !packet.option_exist("DETAILS")
	|| strcmp(packet.get_option("DETAILS").c_str(), "ACCESS GRANTED")) {
		auth_fail = true;
		goto err;
	}

	/// OK !!////////////
	// we won't handle logout, hope bnac server has session timeout
	// DEL
	// IP:172.21.220.168

	ret = true;
err:
	if(auth_sock != INVALID_SOCKET) {
		close_socket(auth_sock);
		auth_sock = INVALID_SOCKET;
	}
	return ret;
}

static bool check_connection(const std::string server, uint16_t port)
{
	SOCKET sock_check = INVALID_SOCKET;
	bool ret = false;
	// make connection
	if((sock_check = make_connection(server, port)) == INVALID_SOCKET) {
		goto err;
	}

	ret = true;

err:
	if(sock_check != INVALID_SOCKET) {
		close_socket(sock_check);
		sock_check = INVALID_SOCKET;
	}
	return ret;
}

#ifdef WIN32
void sleep(int sec)
{
	Sleep(sec * 1000);
}
#endif

static void keep_alive(const std::string & server, uint16_t port, const std::string & session_id,
	const std::string & user, int cipher_num)
{
	struct sockaddr_in server_addr;
	SOCKET sc_keep_alive = INVALID_SOCKET;
	int namelen = 0;
	packet_t packet;
	int index = 1;
	char buffer[4096];
	uint32_t real_len, packet_len;
	std::ostringstream s;
	std::string index_str;
	uint32_t n, r;
	struct hostent * hostp = NULL;

	hostp = gethostbyname(server.c_str());
	if(!hostp) {
		goto err;
	}

	namelen =  sizeof(server_addr);
	memset(&server_addr, 0, namelen);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	memcpy(&server_addr.sin_addr, hostp->h_addr, sizeof(server_addr.sin_addr));

	// make socket
	sc_keep_alive = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(INVALID_SOCKET == sc_keep_alive) {
		goto err;
	}

	//KEEP_ALIVE
	//SESSIONID:13756963409705689
	//USER:xxx
	//AUTH_TYPE:DOMAIN
	//HEARTBEAT_INDEX:1  // 不断累积

	packet.set_header("KEEP_ALIVE");
	packet.set_option("SESSIONID", session_id.c_str());
	packet.set_option("USER", user.c_str());
	packet.set_option("AUTH_TYPE", "DOMAIN");
	s << index;
	index_str = s.str();
	packet.set_option("HEARTBEAT_INDEX", index_str.c_str());

	while(1) {
		real_len = packet.to_buffer(buffer + sizeof(real_len), sizeof(buffer) - sizeof(real_len));
		if(real_len == 0)
			break;

		memcpy(buffer, &real_len, sizeof(real_len));

		n = real_len / 16;
		r = real_len % 16;

		if(r != 0) {
			packet_len = (n+1)*16;
		} else {
			packet_len = n*16;
		}

		if(packet_len + sizeof(real_len)> sizeof(buffer))
			break;

		if(!enc_buffer(buffer + sizeof(uint32_t), real_len, packet_len, cipher_num))
			break;

		if(sendto(sc_keep_alive, buffer, packet_len + sizeof(uint32_t), 0,
			(const struct sockaddr*)&server_addr, namelen) < 0 ) {
			socket_error("sendto:");
			break;
		}

		shout(".");
		if(!check_connection(BNAC_PING_SERVER, BNAC_PING_PORT)) {
			shout("check connection failed\n");
			break;
		}

		sleep(30);
		index ++;
		s.str();
		s << index;
		index_str = s.str();
		packet.set_option("HEARTBEAT_INDEX", index_str.c_str());
	}

	shout("keepalive quit!\n");

err:
	if(sc_keep_alive != INVALID_SOCKET) {
		close_socket(sc_keep_alive);
		sc_keep_alive = INVALID_SOCKET;
	}
	return;
}


static void touch_pid(const std::string & pid_file)
{
	pid_t pid;
	FILE * pid_f = NULL;

	if((pid_f = fopen(pid_file.c_str(), "wb")) != NULL) {
		fprintf(pid_f, "%d", getpid());
		fclose(pid_f);
		pid_f = NULL;
	}
}

static void clear_cmdline(int argc, char ** argv)
{
	int len = 0;
	int i;
	for(i = 0 ; i < argc ; i ++) {
		len += strlen(argv[i]) + 1;
	}
	memset(argv[0], 0, len);
	snprintf(argv[0], len, "bnac");
}

int main(int argc, char *argv[])
{
	int        option_index = 0;
	int        exit_code = 0;
	std::string server = BNAC_SERVER;
	uint16_t    port = BNAC_PORT;
	std::string user = "";
	std::string password = "";
	std::string  pid_file = BNAC_PIDFILE;
	std::string  session_id = "";
	std::string  client_id = BNAC_CLIENTID;
	int c;
	bool auth_fail = false;
	int cipher_num = 0;

	while(1) {
#ifdef WIN32
		c = getopt_long (argc, argv, "c:s:P:u:p:vhq", long_options, &option_index);
#else
		c = getopt_long (argc, argv, "c:s:P:u:p:f:Dvhq", long_options, &option_index);
#endif
		if (c == -1)
			break;
			switch(c) {
			case 'c':
				client_id = optarg;
#ifndef WIN32
			case 'f':
				pid_file = optarg;
				break;
			case 'D':
				g_nodaemon = 0;
				break;
#endif
			case 's':
				server = optarg;
				break;
			case 'P':
				port = atoi(optarg);
				break;
			case 'u':
				user = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			case 'v':
				show_version();
				exit_code = BNAC_ERR_OK;
				goto err;
			case 'h':
				show_usage(argv[0]);
				exit_code = BNAC_ERR_OK;
				goto err;
			case 'q':
				g_quiet = 1;
				break;
			}
	}

	if(server.size() == 0 || password.size() == 0 || user.size() == 0 || pid_file.size() == 0) {
		show_usage(argv[0]);
		exit_code = BNAC_ERR_INVALID_PARAM;
		goto err;
	}
#ifndef WIN32
	if(!g_nodaemon) {
		daemon(0,0);
	}

	touch_pid(pid_file);
#endif

	clear_cmdline(argc, argv);

	if(!init_socket()){
		exit_code = BNAC_ERR_SYSTEM;
		goto err;
	}

	while(1) {
		//static bool auth(const std::string & user, const std::string & password, 
			//const std::string & server, uint16_t port, std::string & session_id, int & cipher_num, bool & auth_fail)
		if(auth(client_id, user, password, server, port, session_id, cipher_num, auth_fail)) {
			shout("Login OK, Press Ctl-c to quit!\n");
            shout("*do NOT quit program or you will be kick off*\n");
            keep_alive(server, port, session_id, user, cipher_num);
		} else if(auth_fail){
			shout("Login FAILED!\n");
			exit_code = BNAC_ERR_AUTH_FAIL;
			break;
		} else {
			shout("Auth FAILED!\n");
		}
		sleep(5);
	}// while(1)
err:
	return exit_code;
}
