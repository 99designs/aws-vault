package dbus

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"testing"
)

func TestSessionBus(t *testing.T) {
	_, err := SessionBus()
	if err != nil {
		t.Error(err)
	}
}

func TestSystemBus(t *testing.T) {
	_, err := SystemBus()
	if err != nil {
		t.Error(err)
	}
}

func TestSend(t *testing.T) {
	bus, err := SessionBus()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan *Call, 1)
	msg := &Message{
		Type:  TypeMethodCall,
		Flags: 0,
		Headers: map[HeaderField]Variant{
			FieldDestination: MakeVariant(bus.Names()[0]),
			FieldPath:        MakeVariant(ObjectPath("/org/freedesktop/DBus")),
			FieldInterface:   MakeVariant("org.freedesktop.DBus.Peer"),
			FieldMember:      MakeVariant("Ping"),
		},
	}
	call := bus.Send(msg, ch)
	<-ch
	if call.Err != nil {
		t.Error(call.Err)
	}
}

func TestRemoveSignal(t *testing.T) {
	bus, err := NewConn(nil)
	if err != nil {
		t.Error(err)
	}
	ch := make(chan *Signal)
	ch2 := make(chan *Signal)
	for _, ch := range []chan *Signal{ch, ch2, ch, ch2, ch2, ch} {
		bus.Signal(ch)
	}
	if len(bus.signals) != 6 {
		t.Errorf("remove signal: signals length not equal: got '%d', want '6'", len(bus.signals))
	}
	bus.RemoveSignal(ch)
	if len(bus.signals) != 3 {
		t.Errorf("remove signal: signals length not equal: got '%d', want '3'", len(bus.signals))
	}
	for _, bch := range bus.signals {
		if bch != ch2 {
			t.Errorf("remove signal: removed signal present: got '%v', want '%v'", bch, ch2)
		}
	}
}

type rwc struct {
	io.Reader
	io.Writer
}

func (rwc) Close() error { return nil }

type fakeAuth struct {
}

func (fakeAuth) FirstData() (name, resp []byte, status AuthStatus) {
	return []byte("name"), []byte("resp"), AuthOk
}

func (fakeAuth) HandleData(data []byte) (resp []byte, status AuthStatus) {
	return nil, AuthOk
}

func TestCloseBeforeSignal(t *testing.T) {
	reader, pipewriter := io.Pipe()
	defer pipewriter.Close()
	defer reader.Close()

	bus, err := NewConn(rwc{Reader: reader, Writer: ioutil.Discard})
	if err != nil {
		t.Fatal(err)
	}
	// give ch a buffer so sends won't block
	ch := make(chan *Signal, 1)
	bus.Signal(ch)

	go func() {
		_, err := pipewriter.Write([]byte("REJECTED name\r\nOK myuuid\r\n"))
		if err != nil {
			t.Errorf("error writing to pipe: %v", err)
		}
	}()

	err = bus.Auth([]Auth{fakeAuth{}})
	if err != nil {
		t.Fatal(err)
	}

	err = bus.Close()
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		Type: TypeSignal,
		Headers: map[HeaderField]Variant{
			FieldInterface: MakeVariant("foo.bar"),
			FieldMember:    MakeVariant("bar"),
			FieldPath:      MakeVariant(ObjectPath("/baz")),
		},
	}
	err = msg.EncodeTo(pipewriter, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
}

type server struct{}

func (server) Double(i int64) (int64, *Error) {
	return 2 * i, nil
}

func BenchmarkCall(b *testing.B) {
	b.StopTimer()
	var s string
	bus, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}
	name := bus.Names()[0]
	obj := bus.BusObject()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := obj.Call("org.freedesktop.DBus.GetNameOwner", 0, name).Store(&s)
		if err != nil {
			b.Fatal(err)
		}
		if s != name {
			b.Errorf("got %s, wanted %s", s, name)
		}
	}
}

func BenchmarkCallAsync(b *testing.B) {
	b.StopTimer()
	bus, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}
	name := bus.Names()[0]
	obj := bus.BusObject()
	c := make(chan *Call, 50)
	done := make(chan struct{})
	go func() {
		for i := 0; i < b.N; i++ {
			v := <-c
			if v.Err != nil {
				b.Error(v.Err)
			}
			s := v.Body[0].(string)
			if s != name {
				b.Errorf("got %s, wanted %s", s, name)
			}
		}
		close(done)
	}()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		obj.Go("org.freedesktop.DBus.GetNameOwner", 0, c, name)
	}
	<-done
}

func BenchmarkServe(b *testing.B) {
	b.StopTimer()
	srv, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}
	cli, err := SessionBusPrivate()
	if err != nil {
		b.Fatal(err)
	}
	if err = cli.Auth(nil); err != nil {
		b.Fatal(err)
	}
	if err = cli.Hello(); err != nil {
		b.Fatal(err)
	}
	benchmarkServe(b, srv, cli)
}

func BenchmarkServeAsync(b *testing.B) {
	b.StopTimer()
	srv, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}
	cli, err := SessionBusPrivate()
	if err != nil {
		b.Fatal(err)
	}
	if err = cli.Auth(nil); err != nil {
		b.Fatal(err)
	}
	if err = cli.Hello(); err != nil {
		b.Fatal(err)
	}
	benchmarkServeAsync(b, srv, cli)
}

func BenchmarkServeSameConn(b *testing.B) {
	b.StopTimer()
	bus, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}

	benchmarkServe(b, bus, bus)
}

func BenchmarkServeSameConnAsync(b *testing.B) {
	b.StopTimer()
	bus, err := SessionBus()
	if err != nil {
		b.Fatal(err)
	}

	benchmarkServeAsync(b, bus, bus)
}

func benchmarkServe(b *testing.B, srv, cli *Conn) {
	var r int64
	var err error
	dest := srv.Names()[0]
	srv.Export(server{}, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	obj := cli.Object(dest, "/org/guelfey/DBus/Test")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = obj.Call("org.guelfey.DBus.Test.Double", 0, int64(i)).Store(&r)
		if err != nil {
			b.Fatal(err)
		}
		if r != 2*int64(i) {
			b.Errorf("got %d, wanted %d", r, 2*int64(i))
		}
	}
}

func benchmarkServeAsync(b *testing.B, srv, cli *Conn) {
	dest := srv.Names()[0]
	srv.Export(server{}, "/org/guelfey/DBus/Test", "org.guelfey.DBus.Test")
	obj := cli.Object(dest, "/org/guelfey/DBus/Test")
	c := make(chan *Call, 50)
	done := make(chan struct{})
	go func() {
		for i := 0; i < b.N; i++ {
			v := <-c
			if v.Err != nil {
				b.Fatal(v.Err)
			}
			i, r := v.Args[0].(int64), v.Body[0].(int64)
			if 2*i != r {
				b.Errorf("got %d, wanted %d", r, 2*i)
			}
		}
		close(done)
	}()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		obj.Go("org.guelfey.DBus.Test.Double", 0, c, int64(i))
	}
	<-done
}

func TestGetKey(t *testing.T) {
	keys := "host=1.2.3.4,port=5678,family=ipv4"
	if host := getKey(keys, "host"); host != "1.2.3.4" {
		t.Error(`Expected "1.2.3.4", got`, host)
	}
	if port := getKey(keys, "port"); port != "5678" {
		t.Error(`Expected "5678", got`, port)
	}
	if family := getKey(keys, "family"); family != "ipv4" {
		t.Error(`Expected "ipv4", got`, family)
	}
}
