package server

import (
	"encoding/json"
	"testing"
)

func TestCertificatesIdentifyOwnersOfDevicesWithTheSameName(t *testing.T) {
	h, db, _ := fixture(t)
	for _, statement := range []string{
		`INSERT INTO clients(id,name,created_at) VALUES ('first','Анна',1),('second','Борис',1)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('phone-a','first','Телефон','device-a',1),('phone-b','second','Телефон','device-b',1)`,
		`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name) VALUES ('AA','phone-a','valid',1,4102444800,'cert-a'),('BB','phone-b','revoked',1,4102444800,'cert-b')`,
	} {
		if _, err := db.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	cookie, _ := signIn(t, h)
	w := request(h, "GET", "/api/certificates", "", cookie, "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var certificates []struct {
		Serial   string `json:"serial"`
		Client   string `json:"client"`
		ClientID string `json:"client_id"`
		Device   string `json:"device"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &certificates); err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 {
		t.Fatal("missing certificates")
	}
	for _, certificate := range certificates {
		wantName, wantID := "Анна", "first"
		if certificate.Serial == "BB" {
			wantName, wantID = "Борис", "second"
		}
		if certificate.Client != wantName || certificate.ClientID != wantID || certificate.Device != "Телефон" {
			t.Fatalf("certificate %s has wrong ownership: %+v", certificate.Serial, certificate)
		}
	}
}
