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
  printf("udp-recv [-v] [<hostname>] <port>\n");
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
  int verbose = 0, port, s, recvsize, writesize;
  struct sockaddr_in addr;
  socklen_t addrlen;
  char buffer[BUFFER_SIZE];
#ifdef USE_GETHOSTBYNAME
  struct hostent *host = NULL;
#endif
#ifndef USE_OLDSIGNAL
  struct sigaction sa;
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
  s = socket(PF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    ERROR_EXIT("Cannot open socket.\n");

  /* アドレス情報を作成 */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (hostname) {
    /* 特定のアドレスでのみ受信する */
#ifdef USE_GETHOSTBYNAME
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
#else
    addr.sin_addr.s_addr = inet_addr(hostname);
#endif
  } else {
    /* すべてのアドレスで受信する */
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  addrlen = sizeof(addr);

  /* アドレスを設定 */
  if (bind(s, (struct sockaddr *)&addr, addrlen) < 0)
    ERROR_EXIT("Cannot bind.\n");

  /* シグナルハンドラを登録 */
#ifndef USE_OLDSIGNAL
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  if (sigaction(SIGINT, &sa, NULL) < 0)
#else
  if (signal(SIGINT, sigint_handler) == SIG_ERR)
#endif
    ERROR_EXIT("Cannot set signal.\n");

  /* データの受信 */
  memset(&addr, 0, sizeof(addr));
  addrlen = sizeof(addr);
  recvsize = recvfrom(s, buffer, sizeof(buffer), 0,
		      (struct sockaddr *)&addr, &addrlen);
  if (recvsize < 0)
    GOTO_DONE("Cannot recv.\n");
  if (recvsize == sizeof(buffer))
    ERROR_EXIT("Out of buffer.\n");

  VLOG("Recv size on UDP:\t%d\n", recvsize);

  /* 標準出力にデータを書き出す */
  writesize = write(1, buffer, recvsize);
  if (writesize < 0)
    GOTO_DONE("Cannot write.\n");
  VLOG("\n");

  VLOG("Write size to stdout:\t%d\n", writesize);

done:
  if (terminated)
    LOG("Terminated.\n");

  /* ソケットのクローズ */
#ifndef WIN32
  close(s);
#else
  closesocket(s);
#endif

  return 0;
}
