package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/beevik/ntp"
	"github.com/labstack/echo"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

type Pkt struct {
	Time        int64  `json:"time"`
	Syn         bool   `json:"syn"`
	Fin         bool   `json:"fin"`
	DataLength  int    `json:"data_length"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Tos         int    `json:"tos"`
}

var tempSrcPort Pkt
var tempDstPort Pkt

var BaseTime *ntp.Response

var ipSrc, ipDst, tcpFlags, ipAddr, hex, start, end *regexp.Regexp

var err error

var Pkts []Pkt


func main() {
	// サーバー構築
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		if len(Pkts) == 0{
			return c.JSON(http.StatusInternalServerError,"Not Have Stock")
		}
		// 初期化して送る
		t := Pkts
		Pkts = []Pkt{}
		return c.JSON(http.StatusOK,t)
	})

	// 正規表現定義
	ipSrc = regexp.MustCompile(`IP.SRC_ADDR:`)
	ipDst = regexp.MustCompile(`IP.DST_ADDR:`)
	tcpFlags = regexp.MustCompile(`TCP.FLAGS:`)

	// IPアドレス
	ipAddr = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	// 16進数
	hex = regexp.MustCompile(`(0x[a-fA-F0-9]+)`)
	// パケット関連
	start = regexp.MustCompile(`-- ([0-9]+) --`)
	end = regexp.MustCompile(`==`)

	// TODO:グローバルIPアドレスを取得する。（TODO:インターフェイス見ろよw） os.interface的な FIT.AC.JPはグローバルIPが降ってるので今回は無視
	// 標準時間を取得
	BaseTime, err = ntp.QueryWithOptions("time.google.com", ntp.QueryOptions{})
	if err != nil {
		panic(err)
	}
	// キャプチャするコマンドを生成（同じコマンドを実行すればターミナルで再現できるよ）

	cmdSrcStr := "/pkttools-1.16/pkt-recv -i eth0 TCP.SRC_PORT==443 -a"
	cmdDstStr := "/pkttools-1.16/pkt-recv -i eth0 TCP.DST_PORT==443 -a"
	cmdSrc := exec.Command("sh", "-c", cmdSrcStr)
	cmdDst := exec.Command("sh", "-c", cmdDstStr)

	// コマンドを実行する。
	go func(c *exec.Cmd,temp *Pkt) {
		runCommand(c,temp)
	}(cmdDst,&tempDstPort)
	go func(c2 *exec.Cmd,temp2 *Pkt) {
		runCommand(c2,temp2)
	}(cmdSrc,&tempSrcPort)

	// torを起動する。（Dockerから起動すると起動できないなぜ・・・？）
	exec.Command("/tor-0.3.4.9/src/or/tor","-f","/etc/tor/torrc").Start()
	e.Start(":8585")
}

func pktParse(line string, temp *Pkt) {
	// パケットが完了している場合は変数を初期化。生成時刻を記録
	if start.MatchString(line) {
		*temp = Pkt{Time:-1,Syn:false,Fin:false,DataLength:-1,Source:"",Destination:"",Tos:-1}
		temp.Time = time.Now().Add(BaseTime.ClockOffset).Unix() //時刻記録
		return
	}
	// パケット終了
	if end.MatchString(line) {
		// SYNでもFINでもないパケットは破棄
		if !temp.Syn && !temp.Fin {
			return
		}
		j, err := json.Marshal(&temp)
		if err != nil {
			panic(err)
		}
		// 該当パケットを出力
		fmt.Println(string(j))
		Pkts = append(Pkts,*temp)
		return
	}

	// IPアドレスゾーン
	// TODO:ここはDHCPが有効だとローカルIPアドレスになる。（誰か置き換えてローカルIP取得して）（FIT.AC.JPだとグローバル降ってるからいいや）
	// 送信元IPアドレス IP.SRC_ADDR:		136.243.37.214
	if ipSrc.MatchString(line) {
		if ipAddr.MatchString(line) {
			temp.Source = ipAddr.FindString(line)
			//fmt.Println("SRC IP ADDR:", ipAddr.FindString(line))
		}
	}
	// 送信先IPアドレス IP.DST_ADDR:		192.168.43.55
	if ipDst.MatchString(line) {
		if ipAddr.MatchString(line) {
			temp.Destination = ipAddr.FindString(line)
			//fmt.Println("DST IP ADDR:", ipAddr.FindString(line))
		}
	}

	// フラグゾーン TCP.FLAGS:		0x20がSYN0x11がFIN（FINはFIN ACKで帰ってくるよ）
	if tcpFlags.MatchString(line) {
		if hex.MatchString(line) {
			if hex.FindString(line) == "0x2" {
				temp.Syn = true
				//fmt.Println("TCP FLAGS:", "SYN", hex.FindString(line))
			} else if hex.FindString(line) == "0x11" {
				temp.Fin = true
				//fmt.Println("TCP FLAGS:", "FIN", hex.FindString(line))
			} else {
				//fmt.Println("TCP FLAGS:", hex.FindString(line))
			}
		}
	}
}

func runCommand(cmd *exec.Cmd, temp *Pkt) {
	// stdoutのプロセスを取り出す的な
	outReader, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	// 読み取れるようにする
	var bufout bytes.Buffer
	outReader2 := io.TeeReader(outReader, &bufout)

	// 実行
	if err = cmd.Start(); err != nil {
		return
	}

	// ここでstdour1行1行をスキャン
	go func(r io.Reader,t *Pkt) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			pktParse(scanner.Text(), t)
		}
	}(outReader2,temp)

	// コマンド終了まで待つ
	err = cmd.Wait()
	return
}
