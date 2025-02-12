package internal_test

import (
	"mannemsolutions/pgcustodian/internal"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	assert.NotEmpty(t, internal.GetAppVersion())
	assert.Regexp(t, `v(\d+\.)?(\d+\.)?(\*|\d+)$`, internal.GetAppVersion(), "AppVersion should follow convention")
}
