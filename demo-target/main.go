package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
)

// VULN: chave AWS hardcoded (secret_scan deve mascarar).
const awsKey = "AKIAIOSFODNN7EXAMPLE"

func hashSenha(s string) []byte {
	// VULN: MD5 para hashing (crypto fraco).
	h := md5.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func buscarUsuario(db *sql.DB, id string) {
	// VULN: SQL montado por interpolação (SQL injection).
	q := fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)
	db.Query(q)
}

func chamarAPI() {
	// VULN: http.DefaultClient sem timeout.
	http.DefaultClient.Get("https://exemplo.com/dados")
}

func main() {
	fmt.Println("demo", awsKey)
}
