package main

import (
	"fmt"
	"github.com/beevik/ntp"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
	"os"
	"time"
)

var db *gorm.DB

func main() {
	// Connect mysql database
	InitDB()

	// Echo instance
	e := echo.New()

	baseTime,err := ntp.QueryWithOptions("time.google.com",ntp.QueryOptions{})
	if err != nil{
		panic(err)
	}

	// Route => handler
	e.GET("/", func(c echo.Context) error {
		var log Log
		log.IpAddress = c.QueryParam("ip")
		log.Method = c.Request().Method
		log.Data = c.QueryParam("data")
		log.Time = time.Now().Add(baseTime.ClockOffset)
		db.Create(&log)
		fmt.Println(log)
		return c.String(http.StatusOK, "Hello, World!\n")
	})
	e.GET("/log", func(c echo.Context) error {
		var logs []Log
		db.Find(&logs)
		return c.JSON(http.StatusOK,logs)
	})

	// Start AttackServer
	port := os.Getenv("port")
	if port == ""{
		port = "8000"
	}
	e.Logger.Fatal(e.Start(":" + port))
}

func InitDB(){
	Db,err := gorm.Open("sqlite3","./AttackServer/log.db")
	if err != nil{
		panic(err)
	}
	if !Db.HasTable(&Log{}){
		Db.CreateTable(&Log{})
	}
	db = Db
}

type Log struct {
	IpAddress string
	Method string
	Data string
	Time time.Time
}