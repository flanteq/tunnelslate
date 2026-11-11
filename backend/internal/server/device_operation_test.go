package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestDevicesDescribeTheirOperationAndWholeClientDeletion(t *testing.T) {
	h, db, _ := fixture(t)
	for _, statement := range []string{
		`INSERT INTO clients(id,name,created_at) VALUES ('normal','Normal',0),('removing','Removing',0)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('rotating','normal','Laptop','device-a',0),('revoking','normal','Phone','device-b',0),('deleting','normal','Tablet','device-c',0),('child-a','removing','A','device-d',0),('child-b','removing','B','device-e',0)`,
		`INSERT INTO operations(id,device_id,client_id,kind,state,step,created_at,updated_at) VALUES ('rotate','rotating','normal','rotate','running','issue_certificate',0,0),('revoke','revoking','normal','revoke','pending','queued',0,0),('delete','deleting','normal','delete','partial','disconnect_sessions',0,0),('previous','child-a','removing','issue','succeeded','complete',0,0),('parent',NULL,'removing','delete_client','running','revoke_certificate',0,0)`,
	} {
		if _, err := db.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	// Device state must describe a long-running/partial deletion even when it
	// has been pushed far back in the operation journal by newer entries.
	for i := 0; i < 101; i++ {
		if _, err := db.DB.Exec(`INSERT INTO operations(id,kind,state,step,created_at,updated_at) VALUES (?,'issue','succeeded','complete',0,0)`, fmt.Sprintf("later-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	cookie, _ := signIn(t, h)
	if response := request(h, "GET", "/api/operations", "", cookie, "", ""); response.Code != 200 || !strings.Contains(response.Body.String(), `"id":"parent"`) {
		t.Fatal("operation journal is incomplete", response.Code, response.Body.String())
	}
	for _, parentState := range []string{"pending", "running", "partial", "succeeded"} {
		if _, err := db.DB.Exec("UPDATE operations SET state=? WHERE id='parent'", parentState); err != nil {
			t.Fatal(err)
		}
		response := request(h, "GET", "/api/devices", "", cookie, "", "")
		var devices []struct {
			ID          string `json:"id"`
			State       string `json:"operation_state"`
			Kind        string `json:"operation_kind"`
			OperationID string `json:"operation_id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &devices); err != nil || response.Code != 200 || len(devices) != 5 {
			t.Fatal(response.Code, response.Body.String(), err)
		}
		for _, device := range devices {
			kind, state, id := "", "", ""
			switch device.ID {
			case "rotating":
				kind, state, id = "rotate", "running", "rotate"
			case "revoking":
				kind, state, id = "revoke", "pending", "revoke"
			case "deleting":
				kind, state, id = "delete", "partial", "delete"
			case "child-a", "child-b":
				if parentState != "succeeded" {
					kind, state, id = "delete_client", parentState, "parent"
				} else if device.ID == "child-a" {
					kind, state, id = "issue", "succeeded", "previous"
				}
			}
			if device.Kind != kind || device.State != state || device.OperationID != id {
				t.Fatalf("parent state %s: device %+v, want %s/%s/%s", parentState, device, kind, state, id)
			}
		}
	}
}
