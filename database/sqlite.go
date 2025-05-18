// SQLite initialization
func initDB() {
var err error
db, err = sql.Open("sqlite", "./credentials.db") // Initialize SQLite DB connection
if err != nil {
fmt.Println("Failed to connect to the database:", err)
return
}

createTableSQL := `
		CREATE TABLE IF NOT EXISTS credentials (
			"ip" TEXT NOT NULL,
			"username" TEXT,
			"password" TEXT,
			"type" TEXT,
			PRIMARY KEY (ip, type)
		);
		CREATE TABLE IF NOT EXISTS last_search (
			"query" TEXT
		);
	`
_, err = db.Exec(createTableSQL)
if err != nil {
fmt.Println("Failed to create tables:", err)
}
}

// Store credentials in SQLite
func storeCredential(ip, username, password, ctype string) error {
query := `INSERT OR REPLACE INTO credentials (ip, username, password, type) VALUES (?, ?, ?, ?)`
_, err := db.Exec(query, ip, username, password, ctype)
return err
}

// Retrieve credentials from SQLite
func getCredential(ip, ctype string) (Credential, error) {
var credential Credential
query := `SELECT ip, username, password, type FROM credentials WHERE ip = ? AND type = ?`
err := db.QueryRow(query, ip, ctype).Scan(&credential.IP, &credential.Username, &credential.Password, &credential.Type)
return credential, err
}

// Save the last search query in SQLite
func saveLastSearch(query string) {
_, err := db.Exec(`DELETE FROM last_search`) // Clear previous search
if err != nil {
fmt.Println("Error clearing last search:", err)
return
}
_, err = db.Exec(`INSERT INTO last_search (query) VALUES (?)`, query)
if err != nil {
fmt.Println("Error saving last search:", err)
}
}

// Get the last search query from SQLite
func getLastSearchQuery() string {
var query string
err := db.QueryRow(`SELECT query FROM last_search`).Scan(&query)
if err != nil {
return ""
}
return query
}
