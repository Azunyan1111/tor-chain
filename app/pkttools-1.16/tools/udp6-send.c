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
#ifndef USE_GETHOSTBYNAME
#ifndef USE_NETLIB
#warning Cannot use inet_pton() on Windows?
#warning If an error as "undefined reference to inet_pton" occurred
#warning on the link stage, Please try to use netlib as follows.
#warning $ unzip netlib-X.X.zip ; mv netlib-X.X netlib ; make USE_NETLIB=yes
#else
int inet_pton(int af, const char *src, void *dst);
#endif
#endif
#endif

#define BUFFER_SIZE (1024*80)

#define LOG(args...) do { fprintf(stderr, args); } while (0)
#define VLOG(args...) do { if (verbose) fprintf(stderr, args); } while (0)
#define ERROR_EXIT(args...) do { fprintf(stderr, args); exit(1); } while (0)
#define GOTO_DONE(args...) do { fprintf(stderr, args); goto done; } while (0)

static void help()
{
  printf("udp6-send [-v] <hostname> <port>\n");
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
  char *hostname;
  int verbose = 0, port, s, readsize, sendsize, offset;
  struct sockaddr_in6 addr;
  socklen_t addrlen;
  char buffer[BUFFER_SIZE];
#ifdef USE_GETHOSTBYNAME
  struct hostent *host;
#endif
#ifndef USE_OLDSIGNAL
  struct sigaction sa;
#endif

  argc--; argv++;

  if ((argc > 0) && !strcmp(argv[0], "-v")) {
    verbose = 1;
    argc--; argv++;
  }

  if (argc < 2)
    help();

  hostname = *argv;
  argc--; argv++;
  port = atoi(*argv);
  argc--; argv++;

#ifdef WIN32
  winsock_init();
  if (!isatty(0))
    setmode(0, O_BINARY);
#endif

#ifdef USE_GETHOSTBYNAME
  /* ホスト名からアドレスを取得 */
  host = gethostbyname(hostname);
  if (host == NULL)
    ERROR_EXIT("Cannot resolve hostname.\n");
#endif

  /* ソケットのオープン */
  s = socket(PF_INET6, SOCK_DGRAM, 0);
  if (s < 0)
    ERROR_EXIT("Cannot open socket.\n");

  /* アドレス情報を作成 */
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
#ifdef USE_GETHOSTBYNAME
  memcpy(&addr.sin6_addr, host->h_addr, host->h_length);
#else
  if (inet_pton(AF_INET6, hostname, &addr.sin6_addr) < 1)
    ERROR_EXIT("Invalid address.\n");
#endif
  addrlen = sizeof(addr);

  /* シグナルハンドラを登録 */
#ifndef USE_OLDSIGNAL
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  if (sigaction(SIGINT, &sa, NULL) < 0)
#else
  if (signal(SIGINT, sigint_handler) == SIG_ERR)
#endif
    ERROR_EXIT("Cannot set signal.\n");

  /* 標準入力からデータを読み込む */
  offset = 0;
  while (!terminated) {
#ifndef WIN32
    readsize = read(0, buffer + offset, sizeof(buffer) - offset);
#else
    /*
     * Windowsで標準入力が(パイプでなく)コンソールの場合，read()に与える
     * バッファサイズが大きいとread()が失敗してエラーを返すので，
     * バッファサイズを調整する．
     */
#define MAXSIZE (1024*4)
#define ADJSIZE(size) ((isatty(0) && ((size) > MAXSIZE)) ? MAXSIZE : (size))
    readsize = read(0, buffer + offset, ADJSIZE(sizeof(buffer) - offset));
#endif
    if (readsize < 0)
      GOTO_DONE("Cannot read.\n");
    if (readsize == 0)
      break;
    offset += readsize;
    if (offset == sizeof(buffer))
      ERROR_EXIT("Out of buffer.\n");
  }
  readsize = offset;

  VLOG("Read size from stdin:\t%d\n", readsize);

  /* データの送信 */
  sendsize = sendto(s, buffer, readsize, 0, (struct sockaddr *)&addr, addrlen);
  if (sendsize < 0)
    GOTO_DONE("Cannot send.\n");

  VLOG("Send size on UDP6:\t%d\n", sendsize);

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
