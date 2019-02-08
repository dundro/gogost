// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2017 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

package gost3410

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type PrivateKey struct {
	c    *Curve
	mode Mode
	key  *big.Int
}

func NewPrivateKey(curve *Curve, mode Mode, raw []byte) (*PrivateKey, error) {
	if len(raw) != int(mode) {
		errors.New("Invalid private key length")
	}
	key := make([]byte, int(mode))
	copy(key, raw)
	reverse(key)
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("Zero private key")
	}
	return &PrivateKey{curve, mode, k}, nil
}

func GenPrivateKey(curve *Curve, mode Mode, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, int(mode))
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, err
	}
	return NewPrivateKey(curve, mode, raw)
}

func (prv *PrivateKey) Raw() []byte {
	raw := pad(prv.key.Bytes(), int(prv.mode))
	reverse(raw)
	return raw
}

func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.c.Exp(prv.key, prv.c.Bx, prv.c.By)
	if err != nil {
		return nil, err
	}
	return &PublicKey{prv.c, prv.mode, x, y}, nil
}

func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	e := bytes2big(digest)
	e.Mod(e, prv.c.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, int(prv.mode))
	var err error
	var k *big.Int
	var r *big.Int
	d := big.NewInt(0)
	s := big.NewInt(0)
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, err
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.c.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.c.Exp(k, prv.c.Bx, prv.c.By)
	if err != nil {
		return nil, err
	}
	r.Mod(r, prv.c.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, prv.c.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	return append(
		pad(s.Bytes(), int(prv.mode)),
		pad(r.Bytes(), int(prv.mode))...,
	), nil
}

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveGOST = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var oidPublicKeyGOST = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	// case sm2.P256Sm2():
	// 	return oidNamedCurveP256SM2, true
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}
	return nil, false
}

//func (c *Curve) Exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {

func (k *PrivateKey) GOST3410ToPEM() ([]byte, error) {
	privateKeyBytes := k.key.Bytes()
	// x, y, err := k.c.Exp(k.key, k.c.Bx, k.c.By)

	paddedPrivateKey := make([]byte, 32)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	// omit NamedCurveOID for compatibility as it's optional
	pubKey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: paddedPrivateKey,
		// PublicKey:  asn1.BitString{Bytes: gost3410.Marshal(gost3410.Mode2001, x, y)},
		PublicKey: asn1.BitString{Bytes: pubKey.Marshal()},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}

	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyGOST
	pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurveGOST
	pkcs8Key.PrivateKey = asn1Bytes

	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling sm2 EC key to asn1 [%s]", err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		},
	), nil
}
