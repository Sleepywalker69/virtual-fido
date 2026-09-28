package util

import (
	"sync"
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
)

func TestRequestBuffer(t *testing.T) {
	buffer := MakeRequestBuffer()
	var mu sync.Mutex
	var got []byte
	var wg sync.WaitGroup
	record := func(response []byte) {
		mu.Lock()
		got = append(got, response[0])
		mu.Unlock()
		wg.Done()
	}
	wg.Add(6)
	buffer.Request(1, record)
	buffer.Request(2, record)
	buffer.Request(3, record)
	done := make(chan struct{})
	go func() {
		for i := byte(1); i <= 6; i++ {
			buffer.Respond([]byte{i})
		}
		close(done)
	}()
	buffer.Request(4, record)
	buffer.Request(5, record)
	buffer.Request(6, record)
	<-done
	wg.Wait()
	test.AssertArrEqual(t, got, []byte{1, 2, 3, 4, 5, 6}, "responses were not delivered in order")
}

func TestRequestBufferCancelAndReset(t *testing.T) {
	buffer := MakeRequestBuffer()
	var got []byte
	record := func(response []byte) { got = append(got, response[0]) }
	buffer.Request(1, record)
	buffer.Request(2, record)
	test.Assert(t, buffer.CancelRequest(1), "pending request was not cancelled")
	test.Assert(t, !buffer.CancelRequest(1), "request cancelled twice")
	buffer.Respond([]byte{7})
	test.AssertArrEqual(t, got, []byte{7}, "response went to a cancelled request")

	buffer.Respond([]byte{8}) // queued: nothing pending
	buffer.Reset()
	buffer.Request(3, record)
	test.AssertArrEqual(t, got, []byte{7}, "queued response survived Reset")
	buffer.Reset()
	buffer.Respond([]byte{9})
	test.AssertArrEqual(t, got, []byte{7}, "pending request survived Reset")
}
