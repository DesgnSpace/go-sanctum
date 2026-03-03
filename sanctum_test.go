package sanctum

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var tokenColumns = []string{
	"id", "tokenable_id", "tokenable_type", "name", "token",
	"abilities", "expires_at", "created_at", "last_used_at",
}

func hashPlaintext(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

func TestCheckToken_ValidWithID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	plaintext := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	hashed := hashPlaintext(plaintext)
	bearer := fmt.Sprintf("1|%s", plaintext)

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("1").
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow("1", "42", "App\\Models\\User", "api-token", hashed, `["read","write"]`, nil, time.Now(), nil),
		)

	mock.ExpectExec("UPDATE personal_access_tokens SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	v := NewValidator(DefaultConfig(db))
	token, err := v.CheckToken(bearer)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token.TokenableID != "42" {
		t.Errorf("expected tokenable_id '42', got %s", token.TokenableID)
	}

	if token.TokenableType != "App\\Models\\User" {
		t.Errorf("expected tokenable_type App\\Models\\User, got %s", token.TokenableType)
	}

	if len(token.Abilities) != 2 || token.Abilities[0] != "read" || token.Abilities[1] != "write" {
		t.Errorf("expected abilities [read, write], got %v", token.Abilities)
	}
}

func TestCheckToken_ValidWithUUID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tokenID := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	userID := "01961e42-5b5a-7c90-8d3e-f1a2b3c4d5e6"
	plaintext := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	hashed := hashPlaintext(plaintext)
	bearer := fmt.Sprintf("%s|%s", tokenID, plaintext)

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs(tokenID).
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow(tokenID, userID, "App\\Models\\User", "api-token", hashed, `["*"]`, nil, time.Now(), nil),
		)

	mock.ExpectExec("UPDATE personal_access_tokens SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	v := NewValidator(DefaultConfig(db))
	token, err := v.CheckToken(bearer)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token.ID != tokenID {
		t.Errorf("expected ID %s, got %s", tokenID, token.ID)
	}

	if token.TokenableID != userID {
		t.Errorf("expected tokenable_id %s, got %s", userID, token.TokenableID)
	}
}

func TestCheckToken_ValidWithoutID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	plaintext := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	hashed := hashPlaintext(plaintext)

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE token = \\?").
		WithArgs(hashed).
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow("1", "42", "App\\Models\\User", "api-token", hashed, `["*"]`, nil, time.Now(), nil),
		)

	mock.ExpectExec("UPDATE personal_access_tokens SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	v := NewValidator(DefaultConfig(db))
	token, err := v.CheckToken(plaintext)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token.TokenableID != "42" {
		t.Errorf("expected tokenable_id '42', got %s", token.TokenableID)
	}
}

func TestCheckToken_InvalidSignature(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	wrongHash := hashPlaintext("wrong-plaintext")
	bearer := "1|correct-plaintext"

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("1").
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow("1", "42", "App\\Models\\User", "api-token", wrongHash, `["*"]`, nil, time.Now(), nil),
		)

	v := NewValidator(DefaultConfig(db))
	_, err = v.CheckToken(bearer)

	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestCheckToken_ExpiredViaExpiresAt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	plaintext := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	hashed := hashPlaintext(plaintext)
	bearer := fmt.Sprintf("1|%s", plaintext)
	pastTime := time.Now().Add(-1 * time.Hour)

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("1").
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow("1", "42", "App\\Models\\User", "api-token", hashed, `["*"]`, pastTime, time.Now(), nil),
		)

	v := NewValidator(DefaultConfig(db))
	_, err = v.CheckToken(bearer)

	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestCheckToken_ExpiredViaGlobalExpiration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	plaintext := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	hashed := hashPlaintext(plaintext)
	bearer := fmt.Sprintf("1|%s", plaintext)
	oldCreatedAt := time.Now().Add(-2 * time.Hour)

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("1").
		WillReturnRows(
			sqlmock.NewRows(tokenColumns).
				AddRow("1", "42", "App\\Models\\User", "api-token", hashed, `["*"]`, nil, oldCreatedAt, nil),
		)

	cfg := DefaultConfig(db)
	cfg.ExpirationMinutes = 60

	v := NewValidator(cfg)
	_, err = v.CheckToken(bearer)

	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestCheckToken_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("999").
		WillReturnRows(sqlmock.NewRows(tokenColumns))

	v := NewValidator(DefaultConfig(db))
	_, err = v.CheckToken("999|some-plaintext")

	if err != ErrTokenNotFound {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestCheckToken_EmptyToken(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	v := NewValidator(DefaultConfig(db))
	_, err = v.CheckToken("")

	if err != ErrTokenMissing {
		t.Fatalf("expected ErrTokenMissing, got %v", err)
	}
}

func TestCheckToken_MalformedToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM personal_access_tokens WHERE id = \\?").
		WithArgs("").
		WillReturnRows(sqlmock.NewRows(tokenColumns))

	v := NewValidator(DefaultConfig(db))
	_, err = v.CheckToken("|plaintext")

	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestTokenData_Can(t *testing.T) {
	token := &TokenData{Abilities: []string{"read", "write"}}

	if !token.Can("read") {
		t.Error("expected Can('read') to be true")
	}

	if !token.Can("write") {
		t.Error("expected Can('write') to be true")
	}

	if token.Can("delete") {
		t.Error("expected Can('delete') to be false")
	}
}

func TestTokenData_CanWildcard(t *testing.T) {
	token := &TokenData{Abilities: []string{"*"}}

	if !token.Can("anything") {
		t.Error("expected wildcard to allow any ability")
	}
}

func TestTokenData_Cant(t *testing.T) {
	token := &TokenData{Abilities: []string{"read"}}

	if !token.Cant("write") {
		t.Error("expected Cant('write') to be true")
	}

	if token.Cant("read") {
		t.Error("expected Cant('read') to be false")
	}
}

func TestLoadLocation_DefaultUTC(t *testing.T) {
	os.Unsetenv("APP_TIMEZONE")

	loc := loadLocation()
	if loc != time.UTC {
		t.Errorf("expected UTC, got %v", loc)
	}
}

func TestLoadLocation_ValidTimezone(t *testing.T) {
	os.Setenv("APP_TIMEZONE", "America/New_York")
	defer os.Unsetenv("APP_TIMEZONE")

	loc := loadLocation()
	expected, _ := time.LoadLocation("America/New_York")

	if loc.String() != expected.String() {
		t.Errorf("expected %s, got %s", expected, loc)
	}
}

func TestLoadLocation_InvalidTimezone(t *testing.T) {
	os.Setenv("APP_TIMEZONE", "Invalid/Zone")
	defer os.Unsetenv("APP_TIMEZONE")

	loc := loadLocation()
	if loc != time.UTC {
		t.Errorf("expected UTC fallback, got %v", loc)
	}
}

func TestWithLocation_OverridesEnv(t *testing.T) {
	os.Setenv("APP_TIMEZONE", "America/New_York")
	defer os.Unsetenv("APP_TIMEZONE")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	store := NewSQLStore(db, WithLocation(tokyo))

	if store.location.String() != tokyo.String() {
		t.Errorf("expected %s, got %s", tokyo, store.location)
	}
}

func TestTouchLastUsedAt_UsesLocation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	store := NewSQLStore(db, WithLocation(tokyo))

	mock.ExpectExec("UPDATE personal_access_tokens SET last_used_at").
		WithArgs(sqlmock.AnyArg(), "1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = store.TouchLastUsedAt("1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestPlaceholderFuncs(t *testing.T) {
	if QuestionMark(1) != "?" {
		t.Errorf("expected '?', got %s", QuestionMark(1))
	}

	if DollarSign(1) != "$1" {
		t.Errorf("expected '$1', got %s", DollarSign(1))
	}

	if DollarSign(3) != "$3" {
		t.Errorf("expected '$3', got %s", DollarSign(3))
	}
}
