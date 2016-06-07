package dbus

import "testing"

type lowerCaseExport struct{}

func (export lowerCaseExport) foo() (string, *Error) {
	return "bar", nil
}

// Test typical Export usage.
func TestExport(t *testing.T) {
	connection, err := SessionBus()
	if err != nil {
		t.Fatalf("Unexpected error connecting to session bus: %s", err)
	}

	name := connection.Names()[0]

	connection.Export(server{}, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	object := connection.Object(name, "/org/guelfey/DBus/Test")

	var response int64
	err = object.Call("org.guelfey.DBus.Test.Double", 0, int64(2)).Store(&response)
	if err != nil {
		t.Errorf("Unexpected error calling Double: %s", err)
	}

	if response != 4 {
		t.Errorf("Response was %d, expected 4", response)
	}

	// Now remove export
	connection.Export(nil, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	err = object.Call("org.guelfey.DBus.Test.Double", 0, int64(2)).Store(&response)
	if err == nil {
		t.Error("Expected an error since the export was removed")
	}
}

// Test Export with an invalid path.
func TestExport_invalidPath(t *testing.T) {
	connection, err := SessionBus()
	if err != nil {
		t.Fatalf("Unexpected error connecting to session bus: %s", err)
	}

	err = connection.Export(nil, "foo", "bar")
	if err == nil {
		t.Error("Expected an error due to exporting with an invalid path")
	}
}

// Test Export with an un-exported method. This should not panic, but rather
// result in an invalid method call.
func TestExport_unexportedMethod(t *testing.T) {
	connection, err := SessionBus()
	if err != nil {
		t.Fatalf("Unexpected error connecting to session bus: %s", err)
	}

	name := connection.Names()[0]

	connection.Export(lowerCaseExport{}, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	object := connection.Object(name, "/org/guelfey/DBus/Test")

	var response string
	call := object.Call("org.guelfey.DBus.Test.foo", 0)
	err = call.Store(&response)
	if err == nil {
		t.Errorf("Expected an error due to calling unexported method")
	}
}

// Test typical ExportWithMap usage.
func TestExportWithMap(t *testing.T) {
	connection, err := SessionBus()
	if err != nil {
		t.Fatalf("Unexpected error connecting to session bus: %s", err)
	}

	name := connection.Names()[0]

	mapping := make(map[string]string)
	mapping["Double"] = "double" // Export this method as lower-case

	connection.ExportWithMap(server{}, mapping, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	object := connection.Object(name, "/org/guelfey/DBus/Test")

	var response int64
	err = object.Call("org.guelfey.DBus.Test.double", 0, int64(2)).Store(&response)
	if err != nil {
		t.Errorf("Unexpected error calling double: %s", err)
	}

	if response != 4 {
		t.Errorf("Response was %d, expected 4", response)
	}
}

// Test that ExportWithMap does not export both method alias and method.
func TestExportWithMap_bypassAlias(t *testing.T) {
	connection, err := SessionBus()
	if err != nil {
		t.Fatalf("Unexpected error connecting to session bus: %s", err)
	}

	name := connection.Names()[0]

	mapping := make(map[string]string)
	mapping["Double"] = "double" // Export this method as lower-case

	connection.ExportWithMap(server{}, mapping, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	object := connection.Object(name, "/org/guelfey/DBus/Test")

	var response int64
	// Call upper-case Double (i.e. the real method, not the alias)
	err = object.Call("org.guelfey.DBus.Test.Double", 0, int64(2)).Store(&response)
	if err == nil {
		t.Error("Expected an error due to calling actual method, not alias")
	}
}
