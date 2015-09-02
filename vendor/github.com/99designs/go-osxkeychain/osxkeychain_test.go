package osxkeychain

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestGenericPassword(t *testing.T) {
	attributes := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test with unicode テスト",
		AccountName: "test account with unicode テスト",
	}

	// Add with a blank password.
	err := AddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Try adding again.
	err = AddGenericPassword(&attributes)
	if err != ErrDuplicateItem {
		t.Errorf("expected ErrDuplicateItem, got %s", err)
	}

	// Find the password.
	password, err := FindGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	if string(password) != "" {
		t.Errorf("FindGenericPassword expected empty string, got %s", password)
	}

	// Replace password with itself (a nil password).
	err = RemoveAndAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Replace password with an empty password.
	attributes.Password = []byte("")
	err = RemoveAndAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Replace password with a non-empty password.
	expectedPassword := []byte("long test password \000 with invalid UTF-8 \xc3\x28 and embedded nuls \000")
	attributes.Password = expectedPassword
	err = RemoveAndAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Find the password again.
	password, err = FindGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	if string(password) != string(expectedPassword) {
		t.Errorf("FindGenericPassword expected %s, got %q", expectedPassword, password)
	}

	// Remove password.
	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Try removing again.
	err = FindAndRemoveGenericPassword(&attributes)
	if err != ErrItemNotFound {
		t.Errorf("expected ErrItemNotFound, got %s", err)
	}

	// Try add path of RemoveAndAddGenericPassword.
	err = RemoveAndAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Remove.
	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}
}

// Make sure fields with invalid UTF-8 are detected properly.
func TestInvalidUTF8(t *testing.T) {
	attributes1 := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test with invalid UTF-8 \xc3\x28",
		AccountName: "test account",
	}

	errServiceName := "ServiceName is not a valid UTF-8 string"

	err := AddGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	_, err = FindGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	err = RemoveAndAddGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	err = FindAndRemoveGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	attributes2 := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test",
		AccountName: "test account with invalid UTF-8 \xc3\x28",
	}

	errAccountName := "AccountName is not a valid UTF-8 string"

	err = AddGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	_, err = FindGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	err = RemoveAndAddGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	err = FindAndRemoveGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}
}

func TestGetAllAccountNames(t *testing.T) {
	serviceName := "osxkeychain_test with unicode テスト"

	accountNames, err := GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	attributes := make([]GenericPasswordAttributes, 10)
	for i := 0; i < len(attributes); i++ {
		attributes[i] = GenericPasswordAttributes{
			ServiceName: serviceName,
			AccountName: fmt.Sprintf("test account with unicode テスト %d", i),
		}

		err := AddGenericPassword(&attributes[i])
		if err != nil {
			t.Error(err)
		}
	}

	accountNames, err = GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	if len(accountNames) != len(attributes) {
		t.Fatalf("Expected %d accounts, got %d", len(attributes), len(accountNames))
	}

	for i := 0; i < len(accountNames); i++ {
		if accountNames[i] != attributes[i].AccountName {
			t.Errorf("Expected account name %s, got %s", attributes[i].AccountName, accountNames[i])
		}
	}

	for i := 0; i < len(attributes); i++ {
		err = FindAndRemoveGenericPassword(&attributes[i])
		if err != nil {
			t.Error(err)
		}
	}

	accountNames, err = GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	if len(accountNames) != 0 {
		t.Errorf("Expected no accounts, got %d", len(accountNames))
	}
}

// Test various edge conditions with RemoveAndAddGenericPassword().
func TestRemoveAndAddGenericPassword(t *testing.T) {
	attributes := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test with unicode テスト",
		AccountName: "test account with unicode テスト",
		Password:    []byte("test password"),
	}

	// Make sure that if a malicious actor adds an identical entry
	// after the remove and before the add, an error is raised.
	err := removeAndAddGenericPasswordHelper(&attributes, func() {
		err := AddGenericPassword(&attributes)
		if err != nil {
			t.Error(err)
		}
	})
	if err != ErrDuplicateItem {
		t.Error(err)
	}

	// Make sure that RemoveAndAddGenericPassword() actually does
	// remove an existing entry first.
	err = removeAndAddGenericPasswordHelper(&attributes, func() {
		_, err := FindGenericPassword(&attributes)
		if err != ErrItemNotFound {
			t.Error(err)
		}
	})

	// Remove password.
	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}
}

func TestGenericPasswordWithApplicationAccess(t *testing.T) {
	attributes := GenericPasswordAttributes{
		ServiceName:         "osxkeychain_test",
		AccountName:         "test account",
		Password:            []byte("test"),
		TrustedApplications: []string{"/Applications/Mail.app"},
	}

	err := AddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}
}

func TestCreatingAndDeletingKeychains(t *testing.T) {
	d, err := ioutil.TempDir("", "osxkeychain-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	kf := filepath.Join(d, "test.keychain")

	if err = CreateKeychain(kf, "テスト"); err != nil {
		t.Error(err)
	}

	if _, err := os.Stat(kf); os.IsNotExist(err) {
		t.Fatalf("Keychain file %q should exist", kf)
	}

	if err = DeleteKeychain(kf); err != nil {
		t.Error(err)
	}

	if _, err := os.Stat(kf); os.IsExist(err) {
		t.Fatalf("Keychain file %q shouldn't exist", kf)
	}
}

func TestAddingItemsToSpecificKeychain(t *testing.T) {
	d, err := ioutil.TempDir("", "osxkeychain-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	kf := filepath.Join(d, "test.keychain")

	if err = CreateKeychain(kf, "テスト"); err != nil {
		t.Error(err)
	}

	defer DeleteKeychain(kf)

	attributes := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test",
		AccountName: "test account",
		Password:    []byte("test テスト"),
		Keychain:    []string{kf},
	}

	err = AddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	defaultAccounts, err := GetAllAccountNames("osxkeychain_test")
	if err != nil {
		t.Error(err)
	}
	if len(defaultAccounts) > 0 {
		t.Error("Item was added to default keychains, should have been new keychain")
	}

	newKeychainAccounts, err := GetAllAccountNames("osxkeychain_test", kf)
	if err != nil {
		t.Error(err)
	}
	if len(newKeychainAccounts) == 0 {
		t.Error("Item wasn't found in new keychain")
	}

	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}
}
