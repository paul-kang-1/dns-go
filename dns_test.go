package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDomainName(t *testing.T) {
	res, err := EncodeDomainName("ab.com")
	assert.NoError(t, err)
	// Length of fragment, byte repr of fragment
	assert.EqualValues(t, res[0], 2)
	assert.EqualValues(t, res[1:3], "ab")
	assert.EqualValues(t, res[3], 3)
	assert.EqualValues(t, res[4:7], "com")
	// Check null termination
	assert.EqualValues(t, res[7], 0)
}

func TestPacketFromBytes(t *testing.T) {
	// Raw packet file retrieved via:
	// dig @a.root-servers.net google.com +norecurse
	file, err := os.Open("testfiles/packet.bin")
	assert.NoError(t, err)
	b := make([]byte, 1024)
	_, err = file.Read(b)
	assert.NoError(t, err)
	reader := bytes.NewReader(b)
	var packet DNSPacket
	assert.NoError(t, packet.FromBytes(reader))
	// Check questions
	qs := *packet.Questions
	assert.Equal(t, string(qs[0].Name), "www.google.com")
}

func TestSendQuery(t *testing.T) {
	packet, err := SendQuery("198.41.0.4", "localhost", TypeA)
	assert.NoError(t, err)
	answers := *packet.Answers
	assert.EqualValues(t, answers[0].Data, []byte{127, 0, 0, 1})
}
