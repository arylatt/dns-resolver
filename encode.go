package dns

import (
	"bytes"
	"encoding/binary"
	"strings"
)

func encodeName(name string) []byte {
	encoded := []byte{}
	nameParts := strings.Split(name, ".")

	for _, part := range nameParts {
		encoded = append(encoded, byte(len(part)))

		for _, c := range part {
			encoded = append(encoded, byte(c))
		}
	}

	return append(encoded, 0)
}

func (h Header) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, byte(h.ID>>8), byte(h.ID))
	encoded = append(encoded, 0, 0)
	encoded = append(encoded, byte(h.QuestionCount>>8), byte(h.QuestionCount))
	encoded = append(encoded, byte(h.AnswerCount>>8), byte(h.AnswerCount))
	encoded = append(encoded, byte(h.AuthorityCount>>8), byte(h.AuthorityCount))
	encoded = append(encoded, byte(h.AdditionalCount>>8), byte(h.AdditionalCount))

	if h.QueryResponse {
		encoded[2] |= 1 << 7
	}

	encoded[2] |= h.Opcode << 3

	if h.AuthorativeAnswer {
		encoded[2] |= 1 << 2
	}

	if h.Truncated {
		encoded[2] |= 1 << 1
	}

	if h.RecursionDesired {
		encoded[2] |= 1
	}

	if h.RecursionAvailable {
		encoded[3] |= 1 << 7
	}

	encoded[3] |= h.ResponseCode

	return encoded
}

func (q Question) Encode() []byte {
	encoded := encodeName(q.Name)
	encoded = append(encoded, byte(q.RecordType>>8), byte(q.RecordType))
	encoded = append(encoded, byte(q.RecordClass>>8), byte(q.RecordClass))

	return encoded
}

func (rr ResourceRecord) Encode() []byte {
	encoded := encodeName(rr.Name)
	encoded = append(encoded, byte(rr.Type>>8), byte(rr.Type))
	encoded = append(encoded, byte(rr.Class>>8), byte(rr.Class))
	encoded = append(encoded, byte(rr.TimeToLive>>24), byte(rr.TimeToLive>>16), byte(rr.TimeToLive>>8), byte(rr.TimeToLive))
	encoded = append(encoded, byte(rr.RecordDataLength>>8), byte(rr.RecordDataLength))
	encoded = append(encoded, rr.RecordData...)

	return encoded
}

func (m Message) Encode() (Message, []byte) {
	m.Header.QuestionCount = uint16(len(m.Questions))
	m.Header.AnswerCount = uint16(len(m.Answers))
	m.Header.AuthorityCount = uint16(len(m.Authorities))
	m.Header.AdditionalCount = uint16(len(m.Additional))

	encoded := m.Header.Encode()

	for _, q := range m.Questions {
		encoded = append(encoded, q.Encode()...)
	}

	buf := &bytes.Buffer{}

	binary.Write(buf, binary.BigEndian, encoded)

	return m, buf.Bytes()
}
