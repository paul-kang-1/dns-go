package main

import (
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
