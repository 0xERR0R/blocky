package resolver

import (
	"blocky/config"
	"testing"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

func Test_Chain(t *testing.T) {
	ch := Chain(NewBlockingResolver(chi.NewRouter(),
		config.BlockingConfig{}), NewClientNamesResolver(config.ClientLookupConfig{}))
	c, ok := ch.(ChainedResolver)
	assert.True(t, ok)

	next := c.GetNext()
	assert.NotNil(t, next)
}
func Test_Name(t *testing.T) {
	name := Name(NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{}))
	assert.Equal(t, "BlockingResolver", name)
}
