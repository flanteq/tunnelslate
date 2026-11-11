package passwordhash

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestUnicodeCharacterLimitsAndFullPasswordVerification(t *testing.T) {
	for _, character := range []string{"a", "я", "🔐"} {
		for _, length := range []int{11, 12, 72, 73} {
			value := strings.Repeat(character, length)
			want := length >= 12 && length <= 72
			if ValidNew(value) != want {
				t.Fatalf("wrong policy for %d %s characters", length, character)
			}
			if !want {
				continue
			}
			encoded, err := Hash(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(encoded, value); err != nil {
				t.Fatal("valid password rejected", err)
			}
			// Especially for Cyrillic/emoji, changing characters after the first
			// 72 encoded bytes must invalidate the complete password.
			wrong := strings.Repeat(character, length-1) + "x"
			if err := Verify(encoded, wrong); err == nil {
				t.Fatal("password was truncated")
			}
		}
	}
	first, err := Hash("same-password-value")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash("same-password-value")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("hashes reused a salt")
	}
	if ValidNew("invalid-utf8-\xff") {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestExistingBcryptPasswordsRemainUsableWithoutTruncation(t *testing.T) {
	for _, value := range []string{strings.Repeat("я", 6), strings.Repeat("я", 36)} {
		encoded, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(string(encoded), value); err != nil {
			t.Fatal("existing password rejected", err)
		}
		if err := Verify(string(encoded), value+"extra"); err == nil {
			t.Fatal("incorrect legacy password accepted")
		}
	}
}

func TestMalformedHashesCannotSelectUnboundedWork(t *testing.T) {
	for _, encoded := range []string{"", "$2a$broken", "$unknown$hash", "$pbkdf2-sha256$i=999999999999999999999$x$y", "$pbkdf2-sha256$i=-1$x$y", "$pbkdf2-sha256$i=1$x$y", "$pbkdf2-sha256$i=600000$x$y"} {
		if Verify(encoded, "test-password-value") == nil {
			t.Fatal("malformed hash accepted")
		}
	}
}
