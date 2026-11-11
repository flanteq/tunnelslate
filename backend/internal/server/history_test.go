package server

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestCertificateAndOperationHistoryIncludesRecordsBeyondFormerLimits(t *testing.T) {
	h, db, _ := fixture(t)
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('owner','Owner',0);
 INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('phone','owner','Phone','phone-cn',0)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 521; i++ {
		if _, err := tx.Exec(`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name) VALUES (?,'phone','valid',0,9999999999,?)`, fmt.Sprintf("serial-%03d", i), fmt.Sprintf("cn-%d", i)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO operations(id,kind,state,step,created_at,updated_at,device_id) VALUES (?,'issue','succeeded','complete',0,0,'phone')`, fmt.Sprintf("operation-%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cookie, _ := signIn(t, h)
	for _, tc := range []struct{ path, key, first, last string }{
		{"/api/certificates", "serial", "serial-520", "serial-000"},
		{"/api/operations", "id", "operation-520", "operation-000"},
	} {
		response := request(h, "GET", tc.path, "", cookie, "", "")
		var items []map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil || response.Code != 200 {
			t.Fatalf("%s: %d %v", tc.path, response.Code, err)
		}
		if len(items) != 521 || items[0][tc.key] != tc.first || items[len(items)-1][tc.key] != tc.last {
			t.Fatalf("%s: history was truncated or reordered (%d)", tc.path, len(items))
		}
	}
}
