package server

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeletedProfilesHiddenFromListsButRemainInJournal(t *testing.T) {
	h, db, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	for _, test := range []struct {
		cookie       bool
		csrf, origin string
		code         int
	}{
		{false, "", cfg.PublicURL, 401}, {true, "", cfg.PublicURL, 403}, {true, csrf, "https://evil.test", 403},
	} {
		if test.cookie {
			if w := request(h, "POST", "/api/devices/profile/delete", `{}`, cookie, test.csrf, test.origin); w.Code != test.code {
				t.Fatal(w.Code)
			}
		} else if w := request(h, "POST", "/api/devices/profile/delete", `{}`, nil, test.csrf, test.origin); w.Code != test.code {
			t.Fatal(w.Code)
		}
	}
	for _, statement := range []string{
		`INSERT INTO clients(id,name,created_at) VALUES ('client','Client',1)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at,deleted_at) VALUES ('visible','client','Visible','device-visible',1,NULL),('hidden','client','Hidden','device-hidden',1,1)`,
		`INSERT INTO operations(id,kind,state,step,device_id,created_at,updated_at) VALUES ('visible-op','issue','succeeded','complete','visible',1,1),('hidden-op','delete','succeeded','complete','hidden',1,1)`,
	} {
		if _, err := db.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name,operation_id) VALUES ('AA','visible','valid',1,?,'visible-cert','visible-op'),('BB','hidden','revoked',1,?,'hidden-cert','hidden-op')`, time.Now().Add(time.Hour).Unix(), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/devices", "/api/certificates"} {
		w := request(h, "GET", path, "", cookie, "", "")
		var rows []map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatalf("hidden profile still listed at %s", path)
		}
		if path == "/api/certificates" && rows[0]["client"] != "Client" {
			t.Fatal("certificate owner is missing")
		}
	}
	w := request(h, "GET", "/api/operations", "", cookie, "", "")
	var operations []map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &operations) != nil || len(operations) != 2 {
		t.Fatal("deleted profile journal was lost")
	}
	for _, op := range operations {
		if op["id"] == "hidden-op" && op["device_name"] != "Hidden" {
			t.Fatal("deleted device name missing from journal")
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count); err != nil || count != 2 {
		t.Fatal("certificate history deleted")
	}
}
