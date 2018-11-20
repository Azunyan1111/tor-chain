#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef USE_GETHOSTBYNAME
#include <netdb.h>
#else
#include <arpa/inet.h>
#endif
#else
#include <fcntl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef WIN32
#define USE_OLDSIGNAL
#endif

#define BUFFER_SIZE (1024*80)

#define LOG(args...) do { fprintf(stderr, args); } while (0)
#define VLOG(args...) do { if (verbose) fprintf(stderr, args); } while (0)
#define ERROR_EXIT(args...) do { fprintf(stderr, args); exit(1); } while (0)
#define GOTO_DONE(args...) do { fprintf(stderr, args); goto done; } while (0)

static void help()
{
  printf("tcp-reply [-v] [<hostname>] <port>\n");
  exit(0);
}

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

#ifdef WIN32
int winsock_init()
{
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
    ERROR_EXIT("WSAStartup() failed.\n");
  return 0;
}
#endif

int main(int argc, char *argv[])
{
  char *hostname = NULL;
  int verbose = 0, port, s, accept_s, recvsize, writesize, sendsize;
  int total_recvsize = 0, total_writesize = 0, total_sendsize = 0;
  struct sockaddr_in addr;
  socklen_t addrlen;
  char buffer[BUFFER_SIZE];
#ifdef USE_GETHOSTBYNAME
  struct hostent *host = NULL;
#endif
#ifndef USE_OLDSIGNAL
  struct sigaction sa;
#endif
#ifndef WIN32
  int on = 1;
#else
  BOOL on = TRUE;
#endif

  argc--; argv++;

  if ((argc > 0) && !strcmp(argv[0], "-v")) {
    verbose = 1;
    argc--; argv++;
  }

  if (argc < 1)
    help();

  if (argc > 1) {
    hostname = *argv;
    argc--; argv++;
  }
  port = atoi(*argv);
  argc--; argv++;

#ifdef WIN32
  winsock_init();
  if (!isatty(1))
    setmode(1, O_BINARY);
#endif

#ifdef USE_GETHOSTBYNAME
  if (hostname) {
    /* ホスト名からアドレスを取得 */
    host = gethostbyname(hostname);
    if (host == NULL)
      ERROR_EXIT("Cannot resolve hostname.\n");
  }
#endif

  /* ソケットのオープン */
  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0)
    ERROR_EXIT("Cannot open socket.\n");

  /* アドレスを再利用可能にする */
#ifndef WIN32
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
#else
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
#endif
    ERROR_EXIT("Cannot set socket option.\n");

  /* アドレス情報を作成 */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (hostname) {
    /* 特定のアドレスでの接続のみ受け付ける */
#ifdef USE_GETHOSTBYNAME
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
#else
    addr.sin_addr.s_addr = inet_addr(hostname);
#endif
  } else {
    /* すべてのアドレスでの接続を受け付ける */
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  addrlen = sizeof(addr);

  /* アドレスを設定 */
  if (bind(s, (struct sockaddr *)&addr, addrlen) < 0)
    ERROR_EXIT("Cannot bind.\n");

  /* 接続キューの上限を設定 */
  if (listen(s, 5) < 0)
    ERROR_EXIT("Cannot listen.\n");

  /* クライアントからの接続を待ち受け */
  accept_s = s;
  memset(&addr, 0, sizeof(addr));
  addrlen = sizeof(addr);
  s = accept(accept_s, (struct sockaddr *)&addr, &addrlen);
  if (s < 0)
    ERROR_EXIT("Cannot accept.\n");

  /* シグナルハンドラを登録 */
#ifndef USE_OLDSIGNAL
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  if (sigaction(SIGINT, &sa, NULL) < 0)
#else
  if (signal(SIGINT, sigint_handler) == SIG_ERR)
#endif
    ERROR_EXIT("Cannot set signal.\n");

  while (!terminated) {
    /* データの受信 */
#ifndef WIN32
    recvsize = read(s, buffer, sizeof(buffer));
#else
    recvsize = recv(s, buffer, sizeof(buffer), 0);
#endif
    if (recvsize < 0)
      GOTO_DONE("Cannot recv.\n");
    if (recvsize == 0)
      break;

    VLOG("Recv size on TCP:\t%d\n", recvsize);
    total_recvsize += recvsize;

    /* 標準出力にデータを書き出す */
    writesize = write(1, buffer, recvsize);
    if (writesize < 0)
      GOTO_DONE("Cannot write.\n");
    VLOG("\n");

    VLOG("Write size to stdout:\t%d\n", writesize);
    total_writesize += writesize;

    /* データの送信 */
#ifndef WIN32
    sendsize = write(s, buffer, recvsize);
#else
    sendsize = send(s, buffer, recvsize, 0);
#endif
    if (sendsize < 0)
      GOTO_DONE("Cannot send.\n");

    VLOG("Send size on TCP:\t%d\n", sendsize);
    total_sendsize += sendsize;
  }

done:
  if (terminated)
    LOG("Terminated.\n");

  VLOG("\n");
  VLOG("Total recv size:\t%d\n", total_recvsize);
  VLOG("Total write size:\t%d\n", total_writesize);
  VLOG("Total send size:\t%d\n", total_sendsize);

  /* ソケットのクローズ */
#ifndef WIN32
  shutdown(s, SHUT_RDWR);
  close(s);
  close(accept_s);
#else
  shutdown(s, SD_BOTH);
  closesocket(s);
  closesocket(accept_s);
#endif

  return 0;
}
