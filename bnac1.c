#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define INVALID_SOCKET -1
#define BNAC__VERSION__ "1.0.0.4"
#define BNAC_PORT 10001
#define BNAC_SERVER "172.22.1.20"
#define BNAC_PIDFILE "/var/run/bnac.pid"
#define BNAC_PING_SERVER "www.baidu.com"
#define BNAC_PING_PORT 80

#define BNAC_ERR_OK 0
#define BNAC_ERR_INVALID_PARAM 1
#define BNAC_ERR_AUTH_FAIL 2

static int g_quiet;
static int g_nodaemon = 1;

struct option long_options[] = {
                   {"server", 1, 0, 's'},
                   {"user", 1, 0, 'u'},
                   {"password", 1, 0, 'p'},
                   {"version", 1, 0, 'v'},
                   {"help", 1, 0, 'h'},
                   {"quiet", 1, 0, 'q'},
                   {"pidfile", 1, 0, 'f'},
                   {"daemon", 1, 0, 'D'},
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


static void show_version()
{
	shout("BNAC linux hack version %s, by sTeeL<steel.mental@gmail.com>\n", BNAC__VERSION__);
}

static void show_usage(const char * prog)
{
	show_version();
	shout("Usage: %s -s server -u user -p pass [-q]\n", prog);
}

static char * rsa_enc_pass(const char * password)
{
	static const char * n_str =
	"00acce3743572d4d0f291e9e5d5bcc64166e6189e1339bdd8c071e8cd6e5"
	"5ff156b742bb79acb7172be61b154c8dfe8005079868a71d106d638cda18"
	"a886fc6923e1c1eab879a7f43f6309a6d6d0374ff19dbedb73163840c839"
	"e74e263f3bad66fa1a048af6af0dcc4bb6467874dcbf9f57de23bcc373ad"
	"4b3f8d12f801b9f906f2e87c8d7ad9160bc874d45c16f079b7098eaf7c40"
	"c9dc73eca8328c9d4697fcfaa82aff1fdac50597f99c433d7c2c7d093703"
	"43e2a354a88f81aa934a26cbada64381e9d180f5d5d0b5319cd9bce8e483"
	"f11ac4abc494b4d534a3a8fa004a8463f182952122471f09156ee9feaf9c"
	"31e4e2ed10570cc718772c42e02160e469";

	unsigned char * enc_pass = NULL;
	char * enc_pass_str = NULL;
	RSA *rsa = NULL;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	int pass_len = 0;
	int i = 0;
	int success = 0;

	n = BN_new();
	e = BN_new();

	if(!n || !e)
		goto err;

	if(!BN_hex2bn(&n, n_str))
		goto err;

	if(!(rsa = RSA_generate_key(1024, 65537,NULL,NULL)))
		goto err;

	BN_free(rsa->n);
	rsa->n = n;

	BN_free(rsa->d);
	rsa->d = e;

	pass_len = RSA_size(rsa);

	if(!(enc_pass = malloc(pass_len)))
		goto err;
	memset(enc_pass, 0, pass_len);

	if((pass_len = RSA_public_encrypt(strlen(password), password, enc_pass, rsa, RSA_PKCS1_PADDING)) < 0)
		goto err;

	if(!(enc_pass_str = malloc(pass_len*2+1)))
		goto err;
	memset(enc_pass_str, 0, pass_len*2+1);

	for(i = 0; i < pass_len; i ++) {
		sprintf(enc_pass_str+i*2, "%02X", enc_pass[i]);
	}

	success = 1;
err:
	if(n) BN_free(n);
	if(e) BN_free(e);
	if(enc_pass) free(enc_pass);
	if(success)
		return enc_pass_str;
	if(enc_pass_str) free(enc_pass_str);
	return NULL;
}

static void socket_error(char * fun)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%s errno: %ld\n", fun, errno);
	shout(buf);
}

static int read_res(int sock, char * buffer, int max_len)
{
	int len = 0;
	int ret;
	char b;

	while(len < max_len) {
		ret = recv(sock, &b, 1, 0);
		if(ret > 0 ) {
			buffer[len++] = b;
			if(len >=4 &&
				buffer[len-4] == '\r' &&
				buffer[len-3] == '\n' &&
				buffer[len-2] == '\r' &&
				buffer[len-1] == '\n' ) {
				buffer[len] = 0;
				shout("[READ RES:] \n%s\n", buffer);
				return len;
			}
		} else if(ret == 0) {
			return 0;
		} else {
			socket_error("recv:");
			return -1;
		}
	}
	return -1;
}

static int send_cmd(int sock, const char * buffer, int buf_len)
{
	int ret;
	int sended = 0;
	shout("[SEND CMD:] \n%s\n", buffer);
	while(buf_len > 0) {
		ret = send(sock, buffer + sended, buf_len, 0);
		if(ret > 0) {
			sended += ret;
			buf_len -= ret;
		} else {
			socket_error("send:");
			return -1;
		}
	}
	return sended;
}

static int fill_time(int sock, char * buffer, int len, const char * session_id) // buffer is 32 byte
{
    struct sockaddr_in name;
    char sock_name[256];
    char time_str[256];
    char md5[MD5_DIGEST_LENGTH];
    int sock_len = sizeof(name);
    int i;

	if(len < 33)
		return -1;

    if(getsockname(sock, (struct sockaddr *)&name, &sock_len) < 0) {
        socket_error("getsockname:");
        return -1;
    }

    memset(sock_name, 0, sizeof(sock_name));
    if(inet_ntop(AF_INET, &name, sock_name, sock_len) == NULL) {
        return -1;
    }

    sprintf(time_str, "%s:%s:%s", "liuyan", session_id, sock_name);

    /* md5 it into g_szTime */
    if(MD5(time_str, strlen(time_str), md5) == NULL) {
        shout("md5 error!\n");
        return -1;
    }

    // bin to hex:
	for(i = 0; i < MD5_DIGEST_LENGTH; i ++) {
		sprintf(buffer+i*2, "%2.2X", md5[i]);
	}

    return 0;
}

static char * auth(const char * user, const char * password, const char * server, int * auth_fail)
{
	struct sockaddr_in server_addr;
	int namelen, len;
	char * p = NULL;
	char * t = NULL;
	char * enc_password = NULL;
    int sock = INVALID_SOCKET;

	char cmd[1024];
	char res[1024];
	char time_str[1024];
	char session_id[1024];
	char role[1024];
	char day_to_live[1024];
	char pad[1024];
	char * session_id_ret = NULL;

	enc_password = rsa_enc_pass(password);
	if(NULL == enc_password) {
		goto err;
	}

	// make socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(INVALID_SOCKET == sock) {
		socket_error("socket:");
		goto err;
	}

	// connect to server
	namelen =  sizeof(server_addr);
	memset(&server_addr, 0, namelen);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(BNAC_PORT);
	server_addr.sin_addr.s_addr = inet_addr(server);
	if(connect(sock, (const struct sockaddr*)&server_addr, namelen) !=0 ) {
		socket_error("connect:");
		goto err;
	}

	//send auth cmd
	snprintf(cmd, sizeof(cmd), "AUTH\r\nUSER:%s\r\nPASS:%s\r\nAUTH_TYPE:%s\r\n\r\n",
		user, enc_password, "DOMAIN");

	if(send_cmd(sock, cmd, strlen(cmd)) <= 0)
		goto err;

	// get auth res
	if((len = read_res(sock, res, sizeof(res))) <= 0) {
		if(len == 0) {
			shout("socket closed!\n");
		}
		goto err;
	}

	if(strncmp(res, "288", 3)) {
		// use CMD as tmp buffer
		shout("AUTH failed : %s!\n", res);
		*auth_fail = 1;
		goto err;
	}

	//get ROLE, SESSION_ID, DAY_TO_LIVE, PAD
	p = res;
	while(p - res < len) {
		if(!strncmp(p, "ROLE:", 5))  {
			t = p;
			while (t - res < len && *t != '\r') t++;
			*t = 0;
			strcpy(role, p + 5);
		} else if(!strncmp(p, "SESSION_ID:", 11)) {
			t = p;
			while (t - res < len && *t != '\r') t++;
			*t = 0;
			strcpy(session_id, p + 11);
		} else if(!strncmp(p, "DAY_TO_LIVE:", 12)) {
			t = p;
			while (t - res < len && *t != '\r') t++;
			*t = 0;
			strcpy(day_to_live, p + 12);
		} else if(!strncmp(p, "PAD:", 4)) {
			t = p;
			while (t - res < len && *t != '\r') t++;
			*t = 0;
			strcpy(pad, p + 4);
		}
		p++;
	}

	memset(time_str, 0, sizeof(time_str));
    if(fill_time(sock, time_str, sizeof(time_str), session_id) < 0) {
        goto err;
    }

	// push fack host check....hahahaha
	snprintf(cmd, sizeof(cmd), "PUSH\r\nROLE:%s\r\nTIME:%s\r\nSESSIONID:%s\r\n\r\n",
		role, time_str, session_id);

	if(send_cmd(sock, cmd, strlen(cmd)) <= 0)
		goto err;

	// get host check res
	if((len = read_res(sock, res, sizeof(res))) <= 0) {
		if(len == 0) {
			shout("socket closed!");
		}
		goto err;
	}

	if(strncmp(res, "220", 3)) {
		shout("PUSH failed : %s!\n", res);
		goto err;
	}

	// over!!
	close(sock);
	sock = INVALID_SOCKET;

	if(NULL != enc_password) {
		free(enc_password);
		enc_password = NULL;
	}

	session_id_ret = malloc(strlen(session_id) + 1);
	if(NULL == session_id_ret){
		goto err;
	}

	strcpy(session_id_ret, session_id);

	return session_id_ret;

err:
	if(sock != INVALID_SOCKET)  {
		sock = INVALID_SOCKET;
		close(sock);
	}

	if(NULL != enc_password) {
		free(enc_password);
		enc_password = NULL;
	}

	if(NULL != session_id_ret) {
		free(session_id_ret);
		session_id_ret = NULL;
	}

	return NULL;
}

static void keep_alive(const char * server, const char * session_id, const char * user)
{
	struct sockaddr_in server_addr;
	int sc_keep_alive = INVALID_SOCKET;
	int namelen = 0;
	char cmd[1024];

	namelen =  sizeof(server_addr);
	memset(&server_addr, 0, namelen);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(BNAC_PORT);
	server_addr.sin_addr.s_addr = inet_addr(server);

	// make socket
	sc_keep_alive = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(INVALID_SOCKET == sc_keep_alive) {
		socket_error("socket:");
		goto err;
	}

	// always domain???
	snprintf(cmd, sizeof(cmd), "KEEP_ALIVE\r\nSESSIONID:%s\r\nUSER:%s\r\nAUTH_TYPE:%s\r\n\r\n",
		session_id, user, "DOMAIN");

	while(1) {
		if(sendto(sc_keep_alive, cmd, strlen(cmd), 0, (const struct sockaddr*)&server_addr, namelen) <= 0 ) {
			socket_error("sendto:");
			break;
		}
		shout(".");
		if(check_connect() != 0) {
			break;
		}
		sleep(30);
	}
err:
	if(sc_keep_alive != INVALID_SOCKET) {
		close(sc_keep_alive);
		sc_keep_alive = INVALID_SOCKET;
	}
	return;
}

static void touch_pid(const char * pid_file)
{
	pid_t pid;
	FILE * pid_f = NULL;

	if((pid_f = fopen(pid_file, "wb")) != NULL) {
		fprintf(pid_f, "%d", getpid());
		fclose(pid_f);
		pid_f = NULL;
	}
}

int check_connect()
{
	int sock = INVALID_SOCKET;
	int ret = -1;
	struct sockaddr_in server_addr;
	struct hostent * hostp = NULL;
	int namelen = sizeof(server_addr);

	hostp = gethostbyname(BNAC_PING_SERVER);
	if(!hostp) {
		socket_error("gethostbyname:");
		goto err;
	}

	// make socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(INVALID_SOCKET == sock) {
		socket_error("socket:");
		goto err;
	}

	// connect to server
	namelen =  sizeof(server_addr);
	memset(&server_addr, 0, namelen);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(BNAC_PING_PORT);
	memcpy(&server_addr.sin_addr, hostp->h_addr, sizeof(server_addr.sin_addr));
	if(connect(sock, (const struct sockaddr*)&server_addr, namelen) !=0 ) {
		goto err;
	}

	close(sock);
	sock = INVALID_SOCKET;
	return 0;
err:
	if(sock != INVALID_SOCKET) {
		close(sock);
		sock = INVALID_SOCKET;
	}
	return -1;
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

int main(int argc, char ** argv)
{

	int option_index = 0;
	int exit_code = 0;
	char * enc_pass = NULL;
	char server[256] = BNAC_SERVER;
	char user[256] = {0};
	char password[256] = {0};
	char pid_file[256] = BNAC_PIDFILE;
	char * session_id = NULL;
	int c;
	int auth_fail = 0;

	while(1) {
		c = getopt_long (argc, argv, "s:u:p:f:Dvhq", long_options, &option_index);
		if (c == -1)
			break;
			switch(c) {
			case 'f':
				strncpy(pid_file, optarg, sizeof(pid_file));
				break;
			case 'D':
				g_nodaemon = 0;
				break;
			case 's':
				strncpy(server, optarg, sizeof(server));
				break;
			case 'u':
				strncpy(user, optarg, sizeof(user));
				break;
			case 'p':
				strncpy(password, optarg, sizeof(password));
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

	if(!server[0] || !password[0] || !user[0] || !pid_file[0]) {
		show_usage(argv[0]);
		exit_code = BNAC_ERR_INVALID_PARAM;
		goto err;
	}

	if(!g_nodaemon) {
		daemon(0,0);
	}

	touch_pid(pid_file);

	clear_cmdline(argc, argv);

	while(1) {

		if((session_id = auth(user, password, server, &auth_fail)) != NULL) {
			shout("Login OK, Press Ctl-c to quit!\n");
            shout("*do NOT quit program or you will be kick off*\n");
            keep_alive(server, session_id, user);
		} else if(auth_fail){
			shout("Login FAILED!\n");
			exit_code = BNAC_ERR_AUTH_FAIL;
			break;
		}
		sleep(5);
	}// while(1)

err:
	if(NULL != session_id) {
		free(session_id);
		session_id = NULL;
	}
	return exit_code;
}

