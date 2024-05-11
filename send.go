package dns

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrIncompleteMessageSent = errors.New("error sending dns message: incomplete message sent")
)

func SendMessage(m Message, server string) (Message, []byte, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return Message{}, nil, err
	}

	defer conn.Close()

	_, msgBytes := m.Encode()
	sent, err := conn.Write(msgBytes)
	if err != nil {
		return Message{}, nil, err
	}

	if sent != len(msgBytes) {
		return Message{}, nil, fmt.Errorf("%w. expected to send %d bytes but only sent %d", ErrIncompleteMessageSent, len(msgBytes), sent)
	}

	response := make([]byte, 512)
	readBytes, err := conn.Read(response)
	if err != nil {
		return Message{}, response, err
	}

	responseMsg, err := DecodeMessage(response[0:readBytes])
	return responseMsg, response[0:readBytes], err
}
