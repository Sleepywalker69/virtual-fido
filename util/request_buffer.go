package util

import "sync"

// RequestBuffer pairs asynchronously produced responses with pending requests.
// Requests are completed in the order they were made, the way a USB endpoint
// completes queued transfers; responses that arrive while nothing is pending
// are queued for the next request.
type RequestBuffer struct {
	lock      sync.Mutex
	waiting   []pendingRequest
	responses [][]byte
}

type pendingRequest struct {
	id      uint32
	respond func([]byte)
}

// maxQueuedResponses bounds the responses held while no request is pending.
const maxQueuedResponses = 1024

func MakeRequestBuffer() *RequestBuffer {
	return &RequestBuffer{}
}

func (buffer *RequestBuffer) Request(id uint32, request func(response []byte)) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if len(buffer.responses) > 0 {
		response := buffer.responses[0]
		buffer.responses = buffer.responses[1:]
		request(response)
		return true
	}
	buffer.waiting = append(buffer.waiting, pendingRequest{id: id, respond: request})
	return false
}

func (buffer *RequestBuffer) CancelRequest(id uint32) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	for i, pending := range buffer.waiting {
		if pending.id == id {
			buffer.waiting = append(buffer.waiting[:i], buffer.waiting[i+1:]...)
			return true
		}
	}
	return false
}

func (buffer *RequestBuffer) Respond(data []byte) {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if len(buffer.waiting) > 0 {
		next := buffer.waiting[0]
		buffer.waiting = buffer.waiting[1:]
		next.respond(data)
		return
	}
	if len(buffer.responses) >= maxQueuedResponses {
		buffer.responses = buffer.responses[1:]
	}
	buffer.responses = append(buffer.responses, data)
}

// Reset drops every pending request and queued response, e.g. when the host
// that made the requests disconnects.
func (buffer *RequestBuffer) Reset() {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	buffer.waiting = nil
	buffer.responses = nil
}
