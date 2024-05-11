package dns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendMessage_DNSGoogleComA(t *testing.T) {
	assert := assert.New(t)

	m, err := NewQuestionMessage("dns.google.com", RecordTypeA, RecordClassIN, true)
	assert.NoError(err)

	responseMsg, response, err := SendMessage(m, "8.8.8.8:53")

	assert.NoError(err)
	t.Logf("Response bytes: %x", response)
	t.Logf("Response message: %+v", responseMsg)
}

func TestSendMessage_DNSGoogleComNS(t *testing.T) {
	assert := assert.New(t)

	m, err := NewQuestionMessage("dns.google.com", RecordTypeNS, RecordClassIN, false)
	assert.NoError(err)

	server := "198.41.0.4"

	for {
		responseMsg, responseBytes, err := SendMessage(m, fmt.Sprintf("%s:53", server))

		if !assert.NoError(err) {
			break
		}

		if responseMsg.Header.AuthorityCount == 0 {
			t.Fatalf("No authority found from %s", server)
		}

		authority := responseMsg.Authorities[0]
		nextServer := ""
		if authority.RecordDataLength == 4 {
			nextServer = strings.Join(strings.Split(string(authority.RecordData), ""), ".")
		} else {
			nextServer, _ = decodeName(authority.RecordData, responseBytes)
		}

		if responseMsg.Header.AuthorativeAnswer {
			t.Logf("Server: %q -> Authoratative Server: %q", server, nextServer)
			server = nextServer
			break
		}

		t.Logf("Server: %q -> Next: %q", server, nextServer)
		server = nextServer
	}

	m.Questions[0].RecordType = RecordTypeA
	responseMsg, _, err := SendMessage(m, fmt.Sprintf("%s:53", server))

	if assert.NoError(err) {
		assert.True(responseMsg.Header.AuthorativeAnswer)
		assert.GreaterOrEqual(len(responseMsg.Answers), 1)
		addr := fmt.Sprintf("%d.%d.%d.%d", responseMsg.Answers[0].RecordData[0], responseMsg.Answers[0].RecordData[1], responseMsg.Answers[0].RecordData[2], responseMsg.Answers[0].RecordData[3])
		t.Logf("Server: %q -> Answer: %q", server, addr)
		assert.Equal("8.8.8.8", addr)
	}
}
