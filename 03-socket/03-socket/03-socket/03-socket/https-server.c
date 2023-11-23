#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define HTTP 80
#define HTTPS 443

#define OK 200
#define MOVED_PERMANTLY 301
#define PARTIAL_CONTENT 206
#define NOT_FOUND 404

typedef enum Method {UNSUPPORTED, GET} Method;

typedef struct Request {
    enum Method method;
    char *url;
    char *version;
    struct Header *headers;
    char *body;
} Request;

typedef struct Header {
    char *name;
    char *value;
    struct Header *next;
} Header;

void* listen_port(void* port_num);
void handle_http_request(int sock);
void handle_https_request(SSL* ssl);
struct Request* request_decode(const char* raw_requset);
void free_header(struct Header* header);
void free_request(struct Request *request);

void handle_https_request(SSL* ssl)//处理HTTP请求
{
    char request_buf[1024]={0};
    char response_buf[81920]={0};
    int response_len = 0;
    //HTTP响应字符串
	if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}//握手失败

    int bytes = SSL_read(ssl, request_buf, sizeof(request_buf));//接受请求
	if (bytes < 0) {
		perror("SSL_read failed");
		exit(1);
	}
    //printf("ssl request receive\n");

    int code=0;
	int partial = 0;
	FILE* fp;
	struct Request* req = request_decode(request_buf);

	// search file
	char refined_url[100];
	refined_url[0] = '.';
	char* url_dst = refined_url + 1;
	strcpy(url_dst, req->url);

	if ((fp = fopen(refined_url, "r")) == NULL) {
		code = NOT_FOUND;
		response_len += sprintf(response_buf, "%s %d NOT FOUND\r\n", req -> version, code);      
        response_len += sprintf(response_buf + response_len, "\r\n");
	} 
    else{
		int file_len = 0;
        fseek(fp, 0L, SEEK_END);
        file_len = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
		struct Header* h;
		int start = 0;
		int end = file_len - 1; 
		char str_range[15];
		strcpy(str_range, "Range");
		for (h = req -> headers; h; h = h -> next) {
			if (strcmp(h -> name, str_range) == 0) {
				partial = 1;
				sscanf(h -> value, "bytes=%d-%d", &start, &end);
				end += 1;
				break;
			}
		}
		if (partial == 1) {
			code = PARTIAL_CONTENT;
			int read_len = end - start;
			fseek(fp, start, SEEK_SET);
			response_len += sprintf(response_buf, "%s %d PARTIAL CONTENT\r\n", req -> version, code);
			response_len += sprintf(response_buf + response_len, "Content-length: %d\r\n", read_len);
			response_len += sprintf(response_buf + response_len, "\r\n");
			fread(response_buf + response_len, sizeof(char), read_len, fp);
			fseek(fp, 0, SEEK_SET);
			response_len += read_len;
		} 
        else {   
			code = OK;
			fseek(fp, 0, SEEK_SET);
			response_len += sprintf(response_buf, "%s %d OK\r\n", req -> version, code);
			response_len += sprintf(response_buf + response_len, "Content-length: %d\r\n", file_len);
			response_len += sprintf(response_buf + response_len, "\r\n");
			fread(response_buf + response_len, sizeof(char), file_len, fp);
			fseek(fp, 0, SEEK_SET);
			response_len += file_len;
		}
		fclose(fp);
	}       
    SSL_write(ssl, response_buf, strlen(response_buf));//向客户端发送响应
    //printf("ssl response sent\n");
}

void handle_http_request(int sock)//处理HTTP请求
{
    char request_buf[1024]={0};
    int request_len = 0;
    char response_buf[81920]={0};
    int response_len = 0;

    // receive a message from client
    request_len = recv(sock, request_buf, 1024, 0);
    if (request_len <= 0) {
        perror("recv failed\n");
        exit(1);
    }
    //printf("socket request receive\n");
    int code;

    // parse request
    struct Request* req = request_decode(request_buf);

    // 301
    code = MOVED_PERMANTLY;
    char new_url[100];
    strcpy(new_url, "https://10.0.0.1");
    strcat(new_url, req->url);
    response_len += sprintf(response_buf, "%s %d MOVED PERMANENTLY\r\n", req->version, code);
    response_len += sprintf(response_buf + response_len, "Location: %s\r\n", new_url); 
    
    if(send(sock,response_buf,response_len,0) < 0){
        perror("send response failed\n");
        exit(1);
    }
    //printf("socket responese send\n");
}

void *listen_port(void* which_port)
{
    int port = *((int*)which_port);
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);//创建一个SSL上下文结构体

	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}
    //socket使用SSL/TLS通信
	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	//建立socket文件描述符
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	//申请建立连接

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
    //printf("bind success port%d\n",port);
	//将socket文件描述符与监听地址绑定
	listen(sock, 10);//开始监听请求

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		//接受连接请求
		if (csock < 0) {
            //printf("socket fail port%d\n",port);
			perror("Accept failed");
			exit(1);
		}
        //printf("connect success port%d\n",port);
        if(port == HTTP){
            handle_http_request(csock);
            close(csock);
        }
        else{
            SSL *ssl = SSL_new(ctx); 
		    SSL_set_fd(ssl, csock);
		    handle_https_request(ssl);
            SSL_free(ssl);
            close(csock);
        }
		
	}
}

struct Request* request_decode(const char* raw_request) {
    struct Request *req = NULL;
    req = malloc(sizeof(struct Request));
    memset(req, 0, sizeof(struct Request));

    // method=get
    size_t method_len = strcspn(raw_request, " ");
    if (memcmp(raw_request, "GET", strlen("GET")) == 0) {
        req -> method = GET;
    }
    else {
        req -> method = UNSUPPORTED;
    }
    raw_request += (method_len + 1); // move past <SP>

    // parse URL
    size_t url_len = strcspn(raw_request, " ");
    req -> url = malloc(url_len + 1);
    memcpy(req -> url, raw_request, url_len);
    req -> url[url_len] = '\0';
    raw_request += url_len + 1; // move past <SP>

    // parse HTTP version
    size_t version_len = strcspn(raw_request, "\r\n");
    req -> version = malloc(version_len + 1);
    memcpy(req -> version, raw_request, version_len);
    req -> version[version_len] = '\0';
    raw_request += version_len + 2; // move past <CR><LF>

    struct Header* header = NULL, *last = NULL;
    while (raw_request[0] != '\r' || raw_request[1] != '\n') {
        last = header;
        header = malloc(sizeof(struct Header));

        // name
        size_t name_len = strcspn(raw_request, ":");
        header -> name = malloc(name_len + 1);
        memcpy(header -> name, raw_request, name_len);
        header -> name[name_len] = '\0';
        raw_request += name_len + 1; // move past ':'
        while (*raw_request == ' ') {
            raw_request += 1;
        }

        // value
        size_t value_len = strcspn(raw_request, "\r\n");
        header -> value = malloc(value_len + 1);
        memcpy(header -> value, raw_request, value_len);
        header -> value[value_len] = '\0';
        raw_request += value_len + 2; // move past <CR><LF>

        // next
        header -> next = last;
    }
    req -> headers = header;
    raw_request += 2; // move past <CR><LF>

    // body
    size_t body_len = strlen(raw_request);
    req -> body = malloc(body_len + 1);
    memcpy(req -> body, raw_request, body_len);
    req -> body[body_len] = '\0';

    return req;
}

int main(){
    pthread_t thread_1;
    int http_port = HTTP;
    int https_port = HTTPS;

    if(pthread_create(&thread_1,NULL,listen_port,&http_port) != 0){
        perror("Create thread failed");
        exit(1);
    }
    listen_port(&https_port);
    pthread_detach(thread_1);
}