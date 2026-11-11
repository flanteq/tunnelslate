package store

import "tunnelslate/internal/branding"

func secretContext(purpose string) []byte {
	return []byte(branding.ID + "/" + purpose)
}
