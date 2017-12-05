#pragma comment( lib, "ws2_32.lib" ) // 链接Winsock2.h的静态库文件

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<WinSock2.h>
#include <memory.h>

#include<openssl/ssl.h>
#include<openssl/opensslv.h>
#include<openssl/x509.h>
#include<openssl/pem.h>
#include<openssl/crypto.h>
#include<openssl/err.h>
#include<openssl/rsa.h>

#define CERTF "server.crt"
#define KEYF "server.key"
#define CACERT "ca.crt"

char mail_from[4096];
char rcpt_to[5][4096];
char data[4096];
char imf[4096]; //

void main_Client(SOCKET);
int ValidEmail(char*);

SOCKET Init_ServerSocket() {
    // 初始化版本
    WORD version = MAKEWORD(2, 2); //WINSOCK2版本
    WSADATA wsaData;  //储存调用WSAStartup函数返回的Windows Sockets初始化信息
    int err = WSAStartup(version, &wsaData);  //根据version初始化Winsock服务
    if (err != 0)   // 初始化失败
    {
        exit(1);
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) //检查socket版本
    {
        WSACleanup(); //释放分配资源
        exit(1);
    }

    // 创建socket
    SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0); //$1-internet传输 $2-TCP流 $3-TCP/IP协议
    SOCKADDR_IN addrSrv;	//作为服务器端的socket地址
    addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");	// Internet address
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons(465);  //服务器端端口号
    bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)); //绑定套接字
    listen(sockSrv, 5); //监听

    return sockSrv;
}

void Init_SSL() {
	return;

}

void main()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	const SSL_METHOD *Smethod = TLSv1_server_method();
	SSL_CTX *ctx = SSL_CTX_new(Smethod);
	SSL* ssl = SSL_new(ctx);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key\n");
		exit(5);
	}

    SOCKET sockSrv = Init_ServerSocket();
	
    SOCKADDR_IN addrClient;  //客户端地址
    int len = sizeof(SOCKADDR);
    char *sendBuf[] = {
        "220 LX's SMTP Ready\r\n",
        "250 LX's server|250 mail|250 PIPELINING\r\n",
        "250 OK\r\n",
        "250 OK\r\n",
        "354 Start mail input;end with <CR><LF>.<CR><LF>\r\n",
        "250 OK\r\n",
        "250 OK\r\n",
        "QUIT\r\n",
        "550 Invalid User\r\n" }; //发送标示符

    // 启动！
	X509* client_cert;
	char* str;
    char tempbuf1[4096] = "";
    while (1)  //等待客户请求
    {
        SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len); //队列非空则sockSrv抽取第一个链接，否则阻塞调用进程
		SSL_set_fd(ssl, sockSrv);
		SSL_accept(ssl);





		/*打印所有加密算法的信息(可选)*/
		printf("SSL connection using %s\n", SSL_get_cipher(ssl));

		/*得到服务端的证书并打印些信息(可选) */
		client_cert = SSL_get_peer_certificate(ssl);
		if (client_cert != NULL) {
			printf("Client certificate:\n");

			str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			//CHK_NULL(str);
			printf("\t subject: %s\n", str);
			//Free(str);

			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			//CHK_NULL(str);
			printf("\t issuer: %s\n", str);
			//Free(str);

			X509_free(client_cert);/*如不再需要,需将证书释放 */
		}
		else
			printf("Client does not have certificate.\n");



        FILE *fp;
        fp = fopen("D:\\mail.txt", "w+");
        char recvBuf[4096] = ""; //接收客户端SMTP指令

        memset(rcpt_to, 0, sizeof(rcpt_to));//将recp_to用字符'0'替换
        //SSL_write(ssl, sendBuf[0], strlen(sendBuf[0]));  //向已经连接的套接字sockConn发送连接建立信息：220
		SSL_write(ssl, sendBuf[0], strlen(sendBuf[0]));
        //EHLO
        //SSL_read(ssl, recvBuf, sizeof(recvBuf)); //接收数据 EHLO acer-PC
		SSL_read(ssl, recvBuf, sizeof(recvBuf));
        puts(recvBuf);

        fprintf(fp, "%s\n", recvBuf); //将数据写入文件
        memset(recvBuf, 0, sizeof(recvBuf)); //将recvBuf前4096个字节用字符'0'替换
        SSL_write(ssl, sendBuf[1], strlen(sendBuf[1])); // send:250 OK

        //MAIL FROM
        SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv:MAIL FROM:<...>
        puts(recvBuf);

        if (ValidEmail(recvBuf)) { // 错误邮箱
            SSL_write(ssl, sendBuf[8], strlen(sendBuf[8]));	//send:550
            closesocket(sockConn);
            fclose(fp);
            continue;
        }
        memcpy(mail_from, recvBuf, sizeof(recvBuf));	// 记录mail_from[]
        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[2], strlen(sendBuf[2])); //send:250 OK

        //RCPT TO
        SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv: RCPT TO:<....>
        puts(recvBuf);

        if (ValidEmail(recvBuf)) {
            SSL_write(ssl, sendBuf[8], strlen(sendBuf[8]));
            closesocket(sockConn); fclose(fp);
            continue;
        }
        memcpy(rcpt_to[0], recvBuf, sizeof(recvBuf));	// 记录rcpt_to[]
        puts(recvBuf);

        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[2], strlen(sendBuf[2])); //send:250 OK

        SSL_read(ssl, recvBuf, sizeof(recvBuf));//recv:??
        puts(recvBuf);

        strncpy(tempbuf1, recvBuf, 4);
        //RCPT again if exist, up to 5 times
        int i = 1;
        while ((strcmp(tempbuf1, "RCPT") == 0) && (i < 5))
        {
            if (ValidEmail(recvBuf)) { SSL_write(ssl, sendBuf[8], strlen(sendBuf[8]));	closesocket(sockConn); fclose(fp); continue; }//send:550
            memcpy(rcpt_to[i], recvBuf, sizeof(recvBuf));	// 记录rcpt_to[]
            fprintf(fp, "%s\n", recvBuf);
            memset(recvBuf, 0, sizeof(recvBuf));

            SSL_write(ssl, sendBuf[2], strlen(sendBuf[2])); //send:250 OK
            SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv: RCPT TO:<....>
            strncpy(tempbuf1, recvBuf, 4);
            ++i;
        }

        //DATA
        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[4], strlen(sendBuf[4]));//send:354 Start mail input;end with <CR><LF>.<CR><LF>\r\n

        //real data
        SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv:DATA fragment, ...bytes
        puts(recvBuf);

        memcpy(data, recvBuf, sizeof(recvBuf));	//记录DATA
        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[5], strlen(sendBuf[5])); //send:250 OK

        //邮件格式?
        SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv:IMF
        puts(recvBuf);

        memcpy(imf, recvBuf, sizeof(recvBuf));	//记录imf
        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[6], strlen(sendBuf[6])); //send:250 OK

        //.
        SSL_read(ssl, recvBuf, sizeof(recvBuf)); //recv: .
        puts(recvBuf);

        fprintf(fp, "%s\n", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));
        SSL_write(ssl, sendBuf[7], strlen(sendBuf[7])); //send:QUIT

        //fprintf(fp, "%s\n", recvBuf);

        main_Client(sockConn); //调用客户端函数

        closesocket(sockConn); //关闭套接字

		SSL_free(ssl);
		SSL_CTX_free(ctx);

        fclose(fp);  //关闭文件指针

    }
    WSACleanup(); //释放分配资源
}

SOCKET Init_ClientSocket() {
    // 初始化
    WORD version = MAKEWORD(2, 2); //WINSOCK2版本
    WSADATA wsaData;  //储存调用WSAStartup函数返回的Windows Sockets初始化信息
    int err = WSAStartup(version, &wsaData);  //根据version初始化Winsock服务
    if (err != 0)   // 初始化失败
    {
        exit(1);
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) //检查socket版本
    {
        WSACleanup(); //释放分配资源
        exit(1);
    }

    // 创建socket
    SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0);
    SOCKADDR_IN addrClient;
    addrClient.sin_family = AF_INET;
    addrClient.sin_port = htons(25);

    struct hostent *host;  //主机信息
    host = gethostbyname("mx1.bupt.edu.cn");
    memcpy(&addrClient.sin_addr.S_un.S_addr, host->h_addr_list[0], host->h_length); //将获取的主机IP地址复制到客户端网络地址.32位无符号IPV4地址
    connect(sockClient, (SOCKADDR*)&addrClient, sizeof(SOCKADDR));  //连接套接字

    return sockClient;
}
void main_Client(SOCKET sockCo)
{
    SOCKET sockClient = Init_ClientSocket();

    char *SendBuf[] = {
        "HELO hyde\r\n",
        "DATA\r\n",
        "\r\n.\r\n",
        "QUIT\r\n"
    };

    char arecvBuf[4096] = "";
    char tempbuf[3] = "";
    memset(tempbuf, 0, sizeof(tempbuf));
    memset(arecvBuf, 0, sizeof(arecvBuf));  //初始化arecvBuf

    recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:220 OK

    //HELO
    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, SendBuf[0], strlen(SendBuf[0]), 0); //send:HELO acer_PC
    recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:250 OK
    puts(arecvBuf);

    strncpy(tempbuf, arecvBuf, 3);
    if (strcmp(tempbuf, "250") != 0) { send(sockCo, arecvBuf, strlen(arecvBuf), 0); }	//?

    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, mail_from, strlen(mail_from), 0); //send:MAIL FROM:<...>
    recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:250 OK
    puts(arecvBuf);
    strncpy(tempbuf, arecvBuf, 3);
    if (strcmp(tempbuf, "250") != 0) { send(sockCo, arecvBuf, strlen(arecvBuf), 0); }

    int i = 0;
    while ((rcpt_to[i][0] != 0) && (i<5))
    {
        memset(arecvBuf, 0, sizeof(arecvBuf));
        send(sockClient, rcpt_to[i], strlen(rcpt_to[i]), 0); //send:RCPT TO:<....>
        recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:250 OK
        strncpy(tempbuf, arecvBuf, 3);
        puts(arecvBuf);
        if (strcmp(tempbuf, "250") != 0) { send(sockCo, arecvBuf, strlen(arecvBuf), 0); }
        ++i;
    }

    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, SendBuf[1], strlen(SendBuf[1]), 0); //send: DATA
    recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:354
    puts(arecvBuf);
    strncpy(tempbuf, arecvBuf, 3);
    if (strcmp(tempbuf, "354") != 0) { send(sockCo, arecvBuf, strlen(arecvBuf), 0); }

    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, data, strlen(data), 0);  //send:DATA fragment, ...bytes

    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, imf, strlen(imf), 0);  //send:imf fragment


    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, SendBuf[2], strlen(SendBuf[2]), 0); //send: .
    recv(sockClient, arecvBuf, sizeof(arecvBuf), 0);  //recv:250 OK
    puts(arecvBuf);
    strncpy(tempbuf, arecvBuf, 3);
    if (strcmp(tempbuf, "250") != 0) { send(sockCo, arecvBuf, strlen(arecvBuf), 0); }

    memset(arecvBuf, 0, sizeof(arecvBuf));
    send(sockClient, SendBuf[3], strlen(SendBuf[3]), 0); //send: QUIT

    closesocket(sockClient);

    WSACleanup();
}


int ValidEmail(char *addr)
{
    int flag_d = 0, flag_at = 0, flag_n = 0;
    int at_addr = 0, point_addr = 0, maohao_at = 0;
    int error = 0;
    int i = 0, j = 0;

    for (j; j<strlen(addr); j++)
    {
        if ((maohao_at == 0) && (addr[j] != ':')) { continue; }
        else { maohao_at = i; break; }
    }

    i = j + 3;
    for (; i<(strlen(addr) - 1); i++) //d@nprintf("error=%d\n",error);
    {
        if ((i - j) == 3) //监测第一个字符的合法性
        {
            if (((addr[i]<58) && (addr[i]>47)) || ((addr[i]<91) && (addr[i]>64)) || ((addr[i]<123) && (addr[i]>96)))continue;
            else { error = 1; break; }
        }

        if (flag_at == 0) //监测d合法性
        {
            if (((addr[i]<58) && (addr[i]>47)) || ((addr[i]<91) && (addr[i]>64)) || ((addr[i]<123) && (addr[i]>96)) || (addr[i] == 46))
            {
                if (addr[i] == 46) {
                    if (i == (point_addr + 1)) { error = 1; break; }
                    else { point_addr = i; continue; }
                }
                else { continue; }
            }
            else if (addr[i] == 64) { flag_at = 1;; at_addr = i; continue; }
            else { error = 1; break; }
        }

        if (flag_at == 1) //监测n合法性
        {
            if ((i == at_addr + 1) || (i == (strlen(addr) - 1)))
            {
                if (((addr[i]<58) && (addr[i]>47)) || ((addr[i]<91) && (addr[i]>64)) || ((addr[i]<123) && (addr[i]>96)))continue;
                else { error = 1; break; }
            }
            else
            {
                if (((addr[i]<58) && (addr[i]>47)) || ((addr[i]<91) && (addr[i]>64)) || ((addr[i]<123) && (addr[i]>96)) || (addr[i] == 46))
                {
                    if (addr[i] == 46) {
                        if (i == (point_addr + 1)) { error = 1; break; }
                        else { point_addr = i; continue; }
                    }
                    else continue;
                }
            }
        }
    }
    if (error == 1 || flag_at == 0) error = 1;
    return error;
}
