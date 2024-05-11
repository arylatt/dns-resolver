package dns

import (
	"errors"
	"math/rand"
	"regexp"
)

const (
	RecordTypeA  uint16 = 1
	RecordTypeNS uint16 = 2

	RecordClassIN uint16 = 1

	ExprDomain = `^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$`
)

var (
	ErrInvalidDomain = errors.New("invalid domain name, it must match the expression: " + ExprDomain)

	ErrInvalidHeaderLength = errors.New("invalid header length, header must be at least 12 bytes")

	ErrInvalidMessageLength = errors.New("invalid message length, header must be at least 12 bytes")

	exprDomain = regexp.MustCompile(ExprDomain)
)

type Header struct {
	ID                 uint16
	QueryResponse      bool
	Opcode             byte
	AuthorativeAnswer  bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	ResponseCode       byte
	QuestionCount      uint16
	AnswerCount        uint16
	AuthorityCount     uint16
	AdditionalCount    uint16
}

type Question struct {
	Name                    string
	RecordType, RecordClass uint16
}

type ResourceRecord struct {
	Name             string
	Type             uint16
	Class            uint16
	TimeToLive       uint32
	RecordDataLength uint16
	RecordData       []byte
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additional  []ResourceRecord
}

func NewQuestion(name string, recordType, recordClass uint16) (Question, error) {
	if !exprDomain.MatchString(name) {
		return Question{}, ErrInvalidDomain
	}

	return Question{
		Name:        name,
		RecordType:  recordType,
		RecordClass: recordClass,
	}, nil
}

func NewQuestionMessage(name string, recordType, recordClass uint16, recursionDesired bool) (Message, error) {
	id := uint16(rand.Uint32() & 0xffff)

	question, err := NewQuestion(name, recordType, recordClass)
	if err != nil {
		return Message{}, err
	}

	return Message{
		Header: Header{
			ID:               id,
			RecursionDesired: recursionDesired,
		},
		Questions: []Question{question},
	}, nil
}
