package dns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageEncode(t *testing.T) {
	assert := assert.New(t)

	m, err := NewQuestionMessage("dns.google.com", RecordTypeA, RecordClassIN, true)
	assert.NoError(err)

	m.Header.ID = 22

	m1, encoded := m.Encode()

	m.Header.QuestionCount = 1

	assert.Equal(m, m1)
	assert.Equal("00160100000100000000000003646e7306676f6f676c6503636f6d0000010001", fmt.Sprintf("%x", encoded))
}
