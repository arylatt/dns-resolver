package dns

import "encoding/binary"

func DecodeHeader(encoded []byte) (Header, error) {
	if len(encoded) < 12 {
		return Header{}, ErrInvalidHeaderLength
	}

	h := Header{
		ID:                 binary.BigEndian.Uint16(encoded[0:2]),
		QueryResponse:      encoded[2]>>7 == 1,
		Opcode:             (encoded[2] >> 3) & 0xf,
		AuthorativeAnswer:  (encoded[2]>>2)&1 == 1,
		Truncated:          (encoded[2]>>1)&1 == 1,
		RecursionDesired:   encoded[2]&1 == 1,
		RecursionAvailable: encoded[3]>>7 == 1,
		ResponseCode:       encoded[3] & 0xf,
		QuestionCount:      binary.BigEndian.Uint16(encoded[4:6]),
		AnswerCount:        binary.BigEndian.Uint16(encoded[6:8]),
		AuthorityCount:     binary.BigEndian.Uint16(encoded[8:10]),
		AdditionalCount:    binary.BigEndian.Uint16(encoded[10:12]),
	}

	return h, nil
}

func decodeName(section, message []byte) (string, int) {
	name := ""
	pointer := 0

	for {
		if (section[pointer]>>6)&3 == 3 {
			offset := binary.BigEndian.Uint16([]byte{section[pointer] & 0x3, section[pointer+1]})
			namePart, _ := decodeName(message[offset:], message)

			if len(name) > 0 {
				name += "."
			}

			name += namePart
			break
		}

		length := int(section[pointer])

		if length == 0 {
			break
		}

		if len(name) > 0 {
			name += "."
		}

		name += string(section[pointer+1 : pointer+1+length])

		pointer += length + 1
	}

	return name, pointer + 1
}

func DecodeQuestion(section, message []byte) (Question, int) {
	name, pointer := decodeName(section, message)

	recordType := binary.BigEndian.Uint16(section[pointer : pointer+2])
	recordClass := binary.BigEndian.Uint16(section[pointer+2 : pointer+4])

	return Question{
		Name:        name,
		RecordType:  recordType,
		RecordClass: recordClass,
	}, pointer + 4
}

func DecodeResourceRecord(section, message []byte) (ResourceRecord, int) {
	name, pointer := decodeName(section, message)
	recordType := binary.BigEndian.Uint16(section[pointer+1 : pointer+3])
	recordClass := binary.BigEndian.Uint16(section[pointer+3 : pointer+5])
	timeToLive := binary.BigEndian.Uint32(section[pointer+5 : pointer+9])
	recordDataLength := binary.BigEndian.Uint16(section[pointer+9 : pointer+11])

	return ResourceRecord{
		Name:             name,
		Type:             recordType,
		Class:            recordClass,
		TimeToLive:       timeToLive,
		RecordDataLength: recordDataLength,
		RecordData:       section[pointer+11 : pointer+11+int(recordDataLength)],
	}, pointer + 11 + int(recordDataLength)
}

func DecodeMessage(encoded []byte) (Message, error) {
	if len(encoded) < 12 {
		return Message{}, ErrInvalidMessageLength
	}

	h, err := DecodeHeader(encoded)
	if err != nil {
		return Message{}, err
	}

	m := Message{Header: h}

	pointer := 12

	for i := 0; i < int(h.QuestionCount); i++ {
		q, length := DecodeQuestion(encoded[pointer:], encoded)
		m.Questions = append(m.Questions, q)

		pointer += length
	}

	for i := 0; i < int(h.AnswerCount); i++ {
		rr, length := DecodeResourceRecord(encoded[pointer:], encoded)
		m.Answers = append(m.Answers, rr)

		pointer += length
	}

	for i := 0; i < int(h.AuthorityCount); i++ {
		rr, length := DecodeResourceRecord(encoded[pointer:], encoded)
		m.Authorities = append(m.Authorities, rr)

		pointer += length
	}

	for i := 0; i < int(h.AdditionalCount); i++ {
		rr, length := DecodeResourceRecord(encoded[pointer:], encoded)
		m.Additional = append(m.Additional, rr)

		pointer += length
	}

	return m, nil
}
