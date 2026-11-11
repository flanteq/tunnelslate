package server

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestClientAndDeviceListsIncludeMoreThan500ActiveRecords(t *testing.T) {
	h, db, _ := fixture(t)
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	const count = 521
	for i := 0; i <= count; i++ {
		id := fmt.Sprintf("entry-%03d", i)
		var deletedAt any
		if i == count {
			deletedAt = 1000
		}
		if _, err := tx.Exec("INSERT INTO clients(id,name,created_at,deleted_at) VALUES(?,?,?,?)", id, id, i, deletedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at,deleted_at) VALUES(?,?,?,?,?,?)", id, id, id, id, i, deletedAt); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cookie, _ := signIn(t, h)
	for _, path := range []string{"/api/clients", "/api/devices"} {
		t.Run(path, func(t *testing.T) {
			response := request(h, "GET", path, "", cookie, "", "")
			if response.Code != 200 {
				t.Fatalf("list: %d %s", response.Code, response.Body.String())
			}
			var records []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &records); err != nil {
				t.Fatal(err)
			}
			if len(records) != count {
				t.Fatalf("got %d records, want %d", len(records), count)
			}
			foundOldest := false
			for _, record := range records {
				if record.ID == "entry-000" {
					foundOldest = true
				}
				if record.ID == "entry-521" {
					t.Fatal("archived record is visible")
				}
			}
			if !foundOldest {
				t.Fatal("old client or device missing from list")
			}
		})
	}
}
