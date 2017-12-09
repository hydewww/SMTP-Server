#pragma comment( lib, "ws2_32.lib" ) // 链接Winsock2.h的静态库文
#include<WinSock2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <windows.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <regex>

#define CERTF "server.crt"
#define KEYF "server.key"
#define CACERT "ca.crt"
#define Mail_From 2
#define RCPT_TO 3
#define REC_SIZE 1024

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

char mail_from[2048];
char rcpt_to[5][2048];
char data[2048];
char imf[2048];
char tmpBuff[2048] = "";

unsigned int dest_add[5]; //服务器地址
int n;//转发数


SOCKET Init_SSL_ServerSocket();
SOCKET Init_ServerSocket();
SSL_CTX *Init_SSL();
DWORD WINAPI Ssl_Server(LPVOID lpParameter);
DWORD WINAPI No_Ssl_Server(LPVOID lpParameter);
SOCKET Init_ClientSocket(int i);
void As_Client(SOCKET socketToLocal);
int Email_OK(char *addr, int type);
void Get_Address(char* domain);
void InitFile(char *, char*);
void SSL_RecAndSendData(char* recBuff, const char* sendBuff, SSL* ssl);
void NO_SSL_RecAndSendData(char* recBuff,const char* sendBuff, SOCKET socketToLocal);


SOCKET Init_SSL_ServerSocket() { //初始化ssl socket连接
								 // 初始化版本
	WORD version = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err = WSAStartup(version, &wsaData);
	if (err != 0)
	{
		exit(1);
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) //检查socket版本
	{
		WSACleanup(); //释放分配资源
		exit(1);
	}

	// 创建socket
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;	//作为服务器端的socket地址

	char localHost[256];
	gethostname(localHost, 256);
	hostent *pHost = gethostbyname(localHost);
	memcpy(&addrSrv.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);
	//addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");	// 本地ip
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(465);  //服务器端端口号
	bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)); //绑定套接字
	listen(sockSrv, 5); //监听

	printf("SMTP LocalServer's IP: %s\n", inet_ntoa(addrSrv.sin_addr));
	printf("SMTP LocalServer's port: %d\n", ntohs(addrSrv.sin_port));
	return sockSrv;
}

SOCKET Init_ServerSocket() {//初始化普通socket连接
							// 初始化版本
	WORD version = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err = WSAStartup(version, &wsaData);
	if (err != 0)   // 初始化失败
	{
		exit(1);
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) //检查socket版本
	{
		WSACleanup();
		exit(1);
	}

	// 创建socket
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;	//作为服务器端的socket地址
	char localHost[256];
	gethostname(localHost, 256);
	hostent *pHost = gethostbyname(localHost);
	memcpy(&addrSrv.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(25);  //服务器端端口号
	bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)); //绑定套接字
	listen(sockSrv, 5); //监听

	printf("SMTP LocalServer's IP: %s\n", inet_ntoa(addrSrv.sin_addr));
	printf("SMTP LocalServer's port: %d\n", ntohs(addrSrv.sin_port));
	return sockSrv;
}

SSL_CTX *Init_SSL() { //ssl初始化

	SSL_library_init();//初始化SSL协议
	OpenSSL_add_all_algorithms();//加载运算
	SSL_load_error_strings();

	const SSL_METHOD *Smethod = SSLv23_server_method();//选择会话协议
	SSL_CTX *ctx = SSL_CTX_new(Smethod);//创建会话协议
	SSL_CTX_set_verify(ctx, 0, NULL);//设置证书验证方式
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);//加载CA证书
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {//加载用户证书
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) { //加载用户私钥
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) { //验证私钥和证书是否相等
		printf("Private key does not match the certificate public key\n");
		exit(5);
	}

	return ctx;
}

DWORD WINAPI Ssl_Server(LPVOID lpParameter) //ssl服务器
{
	//printf("Thread 1 begin!\n");
	SSL_CTX *ctx = Init_SSL();
	SOCKET sockSrv = Init_SSL_ServerSocket();

	SOCKADDR_IN addrClient;  //客户端地址
	int len = sizeof(SOCKADDR);
	const char *sendBuff[] = {
		"220 SMTP Ready\r\n",
		"250 server|250 mail|250 PIPELINING\r\n",
		"250 OK\r\n",
		"250 OK\r\n",
		"354 Start mail input;end with <CR><LF>.<CR><LF>\r\n",
		"250 OK\r\n",
		"250 OK\r\n",
		"QUIT\r\n",
		"550 Invalid User\r\n" }; //发送标示符
	//char* send[1] = { "nidasndk" };
	char* send[9];

	X509* client_cert;
	char* str;
	char tmpBuff[2048] = "";
	while (1)  //等待客户请求
	{
		//int n = 0;//一次连接转发数
		// 建立socket
		SOCKET socketToLocal = accept(sockSrv, (SOCKADDR*)&addrClient, &len); //队列非空则sockSrv抽取第一个链接，否则阻塞调用进程
																			  //CHK_ERR(socketToLocal, "accept");
																			  //closesocket(sockSrv);
																			  /*TCP连接已建立,进行服务端的SSL过程. */
		n = 0;
		printf("Begin server side SSL\n");

		// 建立ssl
		SSL* ssl = SSL_new(ctx);//建立SSL套接字
		CHK_NULL(ssl);
		int err = SSL_set_fd(ssl, socketToLocal); //绑定套接字
		SSL_accept(ssl);//完成握手
		CHK_SSL(err);
		/*打印所有加密算法的信息(可选)*/
		printf("SSL connection using %s\n", SSL_get_cipher(ssl));

		// 开始传输
		FILE *fp;

		char filename[20];
		char dataname[21];
		InitFile(filename,dataname);
		fp = fopen(filename, "w+");
		char recBuff[2048] = ""; //接收客户端SMTP指令

		memset(rcpt_to, 0, sizeof(rcpt_to));//将recp_to用字符'0'替换

		SSL_RecAndSendData(recBuff, sendBuff[0], ssl);//向已经连接的                   套接字socketToLocal发送连接建立信息：220
		fprintf(fp, "%s\n", sendBuff[0]);
		fprintf(fp, "%s\n", recBuff); //将数据写入文件

		SSL_RecAndSendData(recBuff, sendBuff[1], ssl);//发送250
		fprintf(fp, "%s\n", sendBuff[1]);
		if (Email_OK(recBuff, Mail_From)) { // 错误邮箱
			SSL_write(ssl, sendBuff[8], strlen(sendBuff[8]));	//send:550
			fprintf(fp, "%s\n", sendBuff[8]);
			closesocket(socketToLocal);
			fclose(fp);
			printf("Email address wrong\n");
			continue;
		}
		memcpy(mail_from, recBuff, sizeof(recBuff));	// 记录mail_from[]
		fprintf(fp, "%s\n", recBuff);
		printf("%s\n", mail_from);

		SSL_RecAndSendData(recBuff, sendBuff[2], ssl);
		fprintf(fp, "%s\n", sendBuff[2]);

		if (Email_OK(recBuff, RCPT_TO)) {
			SSL_write(ssl, sendBuff[8], strlen(sendBuff[8]));
			closesocket(socketToLocal); fclose(fp);
			printf("Email address wrong\n");
			continue;
		}
		memcpy(rcpt_to[0], recBuff, sizeof(recBuff));	// 记录rcpt_to[]
		n++;
		fprintf(fp, "%s\n", recBuff);

		SSL_RecAndSendData(recBuff, sendBuff[2], ssl);
		fprintf(fp, "%s\n", sendBuff[2]);
		strncpy(tmpBuff, recBuff, 4);
		//RCPT again if exist, up to 5 times
		int i = 1;
		while ((strcmp(tmpBuff, "RCPT") == 0) && (i < 5))
		{
			if (Email_OK(recBuff, RCPT_TO)) { SSL_write(ssl, sendBuff[8], strlen(sendBuff[8]));	closesocket(socketToLocal); fclose(fp); 
			printf("Email address wrong\n"); 
			continue; }//send:550
			memcpy(rcpt_to[i], recBuff, sizeof(recBuff));	// 记录rcpt_to[]
			fprintf(fp, "%s\n", recBuff);
			memset(recBuff, 0, sizeof(recBuff));
			n++;

			SSL_write(ssl, sendBuff[2], strlen(sendBuff[2])); //send:250 OK
			fprintf(fp, "%s\n", sendBuff[2]);
			SSL_read(ssl, recBuff, sizeof(recBuff)); //recv: RCPT TO:<....>
			strncpy(tmpBuff, recBuff, 4);
			++i;
		}
		fprintf(fp, "%s\n", recBuff);

		for (int i = 0; i<5; i++) {
			if (strlen(rcpt_to[i]) != 0) {
				printf("%s\n", rcpt_to[i]);
			}
		}
		//DATA
		SSL_RecAndSendData(recBuff, sendBuff[4], ssl);
		fprintf(fp, "%s\n", sendBuff[4]);
		
		memcpy(data, recBuff, sizeof(recBuff));	//记录DATA
		FILE *Fdata = fopen(dataname, "w+");
		fprintf(Fdata, "%s\n", data);
		//fprintf(fp, "%s\n", recBuff);
		//fclose(Fdata);
		printf("The Length of Mail is :%d\n", strlen(data));

		SSL_RecAndSendData(recBuff, sendBuff[5], ssl);
		fprintf(fp, "%s\n", sendBuff[5]);
		memcpy(imf, recBuff, sizeof(recBuff));	//记录imf
		fprintf(fp, "%s\n", recBuff);
		fprintf(Fdata, "%s\n", imf);
		fclose(Fdata);

		SSL_RecAndSendData(recBuff, sendBuff[6], ssl);
		fprintf(fp, "%s\n", sendBuff[6]);
		fprintf(fp, "%s\n", recBuff);

		memset(recBuff, 0, sizeof(recBuff));
		SSL_write(ssl, sendBuff[7], strlen(sendBuff[7])); //send:QUIT
		fprintf(fp, "%s\n", sendBuff[7]);

		As_Client(socketToLocal); //调用客户端函数

		closesocket(socketToLocal); //关闭套接字
		SSL_free(ssl);//关闭套接字
		fclose(fp);  //关闭文件指针
	}

	SSL_CTX_free(ctx);//释放套接字
	WSACleanup(); //释放分配资源	
	printf("Thread 1 quit!\n");

}

DWORD WINAPI No_Ssl_Server(LPVOID lpParameter)//普通服务器
{
	SOCKET sockSrv = Init_ServerSocket();

	SOCKADDR_IN addrClient;  //客户端地址
	int len = sizeof(SOCKADDR);
	const char *sendBuff[] = {
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
	char tmpBuff[4096] = "";
	while (1)  //等待客户请求
	{
		SOCKET socketToLocal = accept(sockSrv, (SOCKADDR*)&addrClient, &len); //队列非空则sockSrv抽取第一个链接，否则阻塞调用进程
		FILE *fp;
		n = 0;

		char filename[20];
		char dataname[21];
		InitFile(filename,dataname);
		fp = fopen(filename, "w+");

		char recBuff[2048] = ""; //接收客户端SMTP指令

		memset(rcpt_to, 0, sizeof(rcpt_to));//将recp_to用字符'0'替换

		NO_SSL_RecAndSendData(recBuff, sendBuff[0], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[0]);
		fprintf(fp, "%s\n", recBuff); //将数据写入文件

		NO_SSL_RecAndSendData(recBuff, sendBuff[1], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[1]);

		if (Email_OK(recBuff, Mail_From)) { // 错误邮箱
			send(socketToLocal, sendBuff[8], strlen(sendBuff[8]), 0);	//send:550
			fprintf(fp, "%s\n", sendBuff[8]);
			closesocket(socketToLocal);
			fclose(fp);
			continue;
		}
		memcpy(mail_from, recBuff, sizeof(recBuff));	// 记录mail_from[]
		fprintf(fp, "%s\n", recBuff);
		printf("%s\n",mail_from);

		NO_SSL_RecAndSendData(recBuff, sendBuff[2], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[2]);

		if (Email_OK(recBuff, RCPT_TO)) {
			send(socketToLocal, sendBuff[8], strlen(sendBuff[8]), 0);
			closesocket(socketToLocal); fclose(fp);
			printf("Email address wrong\n");
			continue;
		}
		++n;
		memcpy(rcpt_to[0], recBuff, sizeof(recBuff));	// 记录rcpt_to[]
		puts(recBuff);

		fprintf(fp, "%s\n", recBuff);

		NO_SSL_RecAndSendData(recBuff, sendBuff[2], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[2]);

		strncpy(tmpBuff, recBuff, 4);
		//RCPT again if exist, up to 5 times
		int i = 1;
		while ((strcmp(tmpBuff, "RCPT") == 0) && (i < 5))
		{
			if (Email_OK(recBuff, RCPT_TO)) { send(socketToLocal, sendBuff[8], strlen(sendBuff[8]), 0);
			printf("Email address wrong\n"); 
			closesocket(socketToLocal); 
			fclose(fp);
			continue; }//send:550
			memcpy(rcpt_to[i], recBuff, sizeof(recBuff));	// 记录rcpt_to[]
			fprintf(fp, "%s\n", recBuff);
			n++;
			memset(recBuff, 0, sizeof(recBuff));


			send(socketToLocal, sendBuff[2], strlen(sendBuff[2]), 0); //send:250 OK
			fprintf(fp, "%s\n", sendBuff[2]);
			recv(socketToLocal, recBuff, sizeof(recBuff), 0); //recv: RCPT TO:<....>
			strncpy(tmpBuff, recBuff, 4);
			++i;
		}


		for (int i = 0; i<5; i++) {
			if (strlen(rcpt_to[i])!=0) {
				printf("%s\n", rcpt_to[i]);
			}
		}

		//DATA
		fprintf(fp, "%s\n", recBuff);
		NO_SSL_RecAndSendData(recBuff, sendBuff[4], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[4]);
		memcpy(data, recBuff, sizeof(recBuff));	//记录DATA
		FILE *Fdata = fopen(dataname, "w+");
		fprintf(Fdata, "%s\n", data);
		//fprintf(fp, "%s\n", recBuff);
		//fclose(Fdata);
		fprintf(fp, "%s\n", recBuff);
		printf("The Length of Mail is :%d\n", strlen(data));

		NO_SSL_RecAndSendData(recBuff, sendBuff[5], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[5]);
		memcpy(imf, recBuff, sizeof(recBuff));	//记录imf
		fprintf(fp, "%s\n", recBuff);
		fprintf(Fdata, "%s\n", imf);
		fclose(Fdata);


		NO_SSL_RecAndSendData(recBuff, sendBuff[6], socketToLocal);
		fprintf(fp, "%s\n", sendBuff[6]);
		fprintf(fp, "%s\n", recBuff);
		memset(recBuff, 0, sizeof(recBuff));
		send(socketToLocal, sendBuff[7], strlen(sendBuff[7]), 0); //send:QUIT
		fprintf(fp, "%s\n", sendBuff[7]);

																  //fprintf(fp, "%s\n", recBuff);

		As_Client(socketToLocal); //调用客户端函数

		closesocket(socketToLocal); //关闭套接字

		fclose(fp);  //关闭文件指针

	}
	WSACleanup(); //释放分配资源
}

SOCKET Init_ClientSocket(int i) {
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
	addrClient.sin_addr.S_un.S_addr = dest_add[i];//获得目的Ip地址
												  //n++;

												  //struct hostent *host;  //主机信息
												  //host = gethostbyname("mx2.qq.com");
												  //memcpy(&addrClient.sin_addr.S_un.S_addr, host->h_addr_list[0], host->h_length); //将获取的主机IP地址复制到客户端网络地址.32位无符号IPV4地址
	connect(sockClient, (SOCKADDR*)&addrClient, sizeof(SOCKADDR));  //连接套接字

	
	printf("SMTP Recive Server's IP: %s\n", inet_ntoa(addrClient.sin_addr));
	printf("SMTP Recive Server's port: %d\n", ntohs(addrClient.sin_port));
	return sockClient;
}

void As_Client(SOCKET socketToLocal)
{
	int i = 0;
	//SOCKET sockClient = Init_ClientSocket();

	const char *sendBuff[] = {
		"HELO hyde\r\n",
		"DATA\r\n",
		"\r\n.\r\n",
		"QUIT\r\n"
	};

	char arecBuff[256] = "";
	char tempbuf[3] = "";
	while ((rcpt_to[i][0] != 0) && (i<5)) //支持多封发送
	{
		SOCKET sockClient = Init_ClientSocket(i);

		memset(tempbuf, 0, sizeof(tempbuf));
		memset(arecBuff, 0, sizeof(arecBuff));  //初始化arecBuff

		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:220 OK

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, sendBuff[0], strlen(sendBuff[0]), 0); //send:HELO acer_PC
		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:250 OK
		//puts(arecBuff);

		strncpy(tempbuf, arecBuff, 3);
		if (strcmp(tempbuf, "250") != 0) { send(socketToLocal, arecBuff, strlen(arecBuff), 0); }	//?

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, mail_from, strlen(mail_from), 0); //send:MAIL FROM:<...>
		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:250 OK
		//puts(arecBuff);

		strncpy(tempbuf, arecBuff, 3);
		if (strcmp(tempbuf, "250") != 0) { send(socketToLocal, arecBuff, strlen(arecBuff), 0); }

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, rcpt_to[i], strlen(rcpt_to[i]), 0); //send:RCPT TO:<....>
		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:250 OK
		strncpy(tempbuf, arecBuff, 3);
		//puts(arecBuff);

		if (strcmp(tempbuf, "250") != 0) { send(socketToLocal, arecBuff, strlen(arecBuff), 0); }

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, sendBuff[1], strlen(sendBuff[1]), 0); //send: DATA
		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:354
		//puts(arecBuff);
		strncpy(tempbuf, arecBuff, 3);
		if (strcmp(tempbuf, "354") != 0) { send(socketToLocal, arecBuff, strlen(arecBuff), 0); }

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, data, strlen(data), 0);  //send:DATA fragment, ...bytes

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, imf, strlen(imf), 0);  //send:imf fragment


		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, sendBuff[2], strlen(sendBuff[2]), 0); //send: .
		recv(sockClient, arecBuff, sizeof(arecBuff), 0);  //recv:250 OK
		//puts(arecBuff);
		strncpy(tempbuf, arecBuff, 3);
		if (strcmp(tempbuf, "250") != 0) { send(socketToLocal, arecBuff, strlen(arecBuff), 0); }

		memset(arecBuff, 0, sizeof(arecBuff));
		send(sockClient, sendBuff[3], strlen(sendBuff[3]), 0); //send: QUIT
		closesocket(sockClient);
		WSACleanup();
		++i;

	}

	//WSACleanup();
}

int Email_OK(char *addr, int type)
{
	int flag_d = 0, flag_at = 0, flag_n = 0;
	int at_addr = 0, point_addr = 0, colon_addr = 0;
	int error = 0;
	int i = 0, j = 0;

	for (j; j<strlen(addr); j++)
	{
		if ((colon_addr == 0) && (addr[j] != ':')) { continue; }
		else { colon_addr = j; break; }
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
	if (error == 1 || flag_at == 0)
	{
		error = 1;
	}
	else if (type == RCPT_TO)
	{
		int ii = 0;
		int iii = 0;
		for (; addr[at_addr + ii + 1] != '>'; ii++)
		{
			//domain[ii] = addr[at_addr + ii+1];
		}
		char* domain = (char*)malloc(ii + 1);
		for (; iii <ii; iii++)
		{
			domain[iii] = addr[at_addr + iii + 1];
		}
		domain[iii] = '\0';
		//printf("%s\n", domain);

		//strncpy(domain, addr, sizeof(domain));
		error = 0;
		Get_Address(domain);
		free(domain);
		domain = NULL;

	}
	else
	{
		error = 0;
	}
	return error;
}

void Get_Address(char* domain)
{

	struct hostent *host;//主机信息
	if (strcmp(domain, "bupt.edu.cn") == 0)
	{
		host = gethostbyname("mx1.bupt.edu.cn");
		memcpy(&dest_add[n], host->h_addr_list[0], host->h_length);
	}
	else if (strcmp(domain, "qq.com") == 0)
	{
		host = gethostbyname("mx1.qq.com");
		memcpy(&dest_add[n], host->h_addr_list[0], host->h_length);
	}
	else if (strcmp(domain, "sina.com") == 0)
	{
		host = gethostbyname("freemx1.sinamail.sina.com.cn");
		memcpy(&dest_add[n], host->h_addr_list[0], host->h_length);
	}
	//memcpy(&dest_add[n], host->h_addr_list[0], host->h_length);
}

void InitFile(char *filename,char* dataname) {

	strcpy(filename, "Log-");
	strcpy(dataname, "Data-");
	char time_now[32];
	time_t time_init;
	struct tm *localTime;

	time_init = time(NULL);
	localTime = localtime(&time_init);
	memset(time_now, 0, sizeof(time_now));
	strftime(time_now, 24, "%Y%m%d%H%M%S", localTime);
	strcat(filename, time_now);
	strcat(filename, ".txt");
	strcat(dataname, time_now);
	strcat(dataname, ".txt");
	memset(time_now, 0, sizeof(time_now));
	strftime(time_now, 24, "%Y/%m/%d %H:%M:%S", localTime);
	printf("Time Now is :%s\n", time_now);


}

void SSL_RecAndSendData(char* recBuff, const char* sendBuff, SSL* ssl) {
	memset(recBuff, 0, sizeof(recBuff));
	SSL_write(ssl, sendBuff, strlen(sendBuff));
	SSL_read(ssl, recBuff, REC_SIZE);
}

void NO_SSL_RecAndSendData(char* recBuff, const char* sendBuff, SOCKET socketToLocal) {
	memset(recBuff, 0, sizeof(recBuff));
	send(socketToLocal, sendBuff, strlen(sendBuff), 0);  
	recv(socketToLocal, recBuff, REC_SIZE, 0); 
}


int main()
{
	HANDLE Ssl;
	HANDLE No_Ssl;
	Ssl = CreateThread(NULL, 0, Ssl_Server, NULL, 0, NULL);
	No_Ssl = CreateThread(NULL, 0, No_Ssl_Server, NULL, 0, NULL);
	//printf("SSl服务开始运行！\n");
	char c;
	while ((c = getchar()) != ('q'))
	{
		;
	}
	CloseHandle(Ssl);
	CloseHandle(No_Ssl);

	return 0;

}