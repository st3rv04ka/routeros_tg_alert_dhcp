package main;

import (
	"flag"
	"fmt"
	"log"
	"database/sql"
	"crypto/md5"
	"encoding/json"
	"net/http"
	"bytes"
	"strings"

	"github.com/go-routeros/routeros"
	_ "github.com/mattn/go-sqlite3"
)

var (
	address  = flag.String("address", "192.168.88.1:8728", "RouterOS address and port")
	username = flag.String("username", "admin", "User name")
	password = flag.String("password", "passowrd", "Password")
	token    = flag.String("token", "XXX", "tg bot token")
	chat_id  = flag.String("chat", "-111111111", "tg chat id")
)

func send_alert(message string, token string, chat_id string) {
	values := map[string]string{"chat_id": chat_id, "text": message, "disable_notification": "true"}
	jsonValue, _ := json.Marshal(values)
	http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token), "application/json", bytes.NewBuffer(jsonValue))
}

func database_init() {
	db, err := sql.Open("sqlite3", "./hash.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	create table IF NOT EXISTS dhcp (hash text);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return
	}

	return 
}

func add_new(hash string) {
	db, err := sql.Open("sqlite3", "./hash.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare("insert into dhcp(hash) values(?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(hash)
	if err != nil {
		log.Fatal(err)
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}

	return
}

func check_hash(hash string) (bool) {
	db, err := sql.Open("sqlite3", "./hash.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt, err := db.Prepare("select hash from dhcp where hash = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	var hash_res string
	err = stmt.QueryRow(hash).Scan(&hash_res)
	if err != nil {
		log.Println(err)
		return false
	}

	if (len(hash_res) > 5) {
		return true
	} else {
		return false
	}
}

func main() {
	database_init()

	flag.Parse()

	c, err := routeros.Dial(*address, *username, *password)
	if err != nil {
		log.Fatal(err)
	}
	
	reply, err := c.Run("/ip/dhcp-server/lease/print", "=.proplist=mac-address,host-name")
	if err != nil {
		log.Fatal(err)
	}

	for _, re := range reply.Re {
		name := ""
		for _, p := range strings.Split("mac-address,host-name", ",") {
			name = name + re.Map[p] + ","  	
		}
		hash := fmt.Sprintf("%x", md5.Sum([]byte(name)))
		if (!check_hash(hash)) {
			send_alert(fmt.Sprintf("New device!\n\n%s", strings.TrimSuffix(name, ",")), *token, *chat_id)
			add_new(hash)
		}
	}
}
