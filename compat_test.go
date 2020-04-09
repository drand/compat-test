package compat

import (
	"testing"

	bls "github.com/drand/bls12-381"
	"github.com/drand/drand/key"
	"github.com/drand/kyber"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

func TestCompatDrand(t *testing.T) {
	drandPoint := key.SigGroup.Point().Pick(random.New())
	blsPoint := bls.NewBLS12381Suite().G2().Point().Pick(random.New())
	hDrand := drandPoint.(hashablePoint)
	hBls := blsPoint.(hashablePoint)
	msg := []byte("Once upon a time")
	drandPoint = hDrand.Hash(msg)
	blsPoint = hBls.Hash(msg)
	require.True(t, drandPoint.Equal(blsPoint))
	drandBuff, err := drandPoint.MarshalBinary()
	require.NoError(t, err)
	blsBuff, err := blsPoint.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, drandBuff, blsBuff)
}
