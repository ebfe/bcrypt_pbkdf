// Package bcrypt_pbkdf provides an implementation of OpenBSD's bcrypt_pbkdf(3)
package bcrypt_pbkdf

import (
	"crypto/sha512"
	"github.com/ebfe/bcrypt_pbkdf/blowfish"
)

//  derived from /usr/src/lib/libutil/bcrypt_pbkdf.c
/*
	$OpenBSD: bcrypt_pbkdf.c,v 1.6 2014/01/31 16:56:32 tedu Exp $

	Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>

	Permission to use, copy, modify, and distribute this software for any
	purpose with or without fee is hereby granted, provided that the above
	copyright notice and this permission notice appear in all copies.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

const (
	bcryptBlocks   = 8
	bcryptHashSize = 4 * bcryptBlocks
	magic          = "OxychromaticBlowfishSwatDynamite"
)

func bcryptHash(hpass, hsalt []byte) []byte {
	bf, err := blowfish.NewSaltedCipher(hpass, hsalt)
	if err != nil {
		panic(err)
	}

	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(hsalt, bf)
		blowfish.ExpandKey(hpass, bf)
	}

	cipher := []byte(magic)

	for i := 0; i < 64; i++ {
		for j := 0; j < bcryptHashSize/blowfish.BlockSize; j++ {
			bf.Encrypt(cipher[j*blowfish.BlockSize:], cipher[j*blowfish.BlockSize:])
		}
	}

	for i := 0; i < len(cipher); i += 4 {
		cipher[i+0], cipher[i+1], cipher[i+2], cipher[i+3] = cipher[i+3], cipher[i+2], cipher[i+1], cipher[i+0]
	}

	return cipher
}

func bcryptPBKDF(password, salt []byte, rounds, keyLen int) []byte {
	countsalt := make([]byte, 4)
	out := make([]byte, bcryptHashSize)
	key := make([]byte, keyLen)

	stride := (keyLen + bcryptHashSize - 1) / bcryptHashSize
	amt := (keyLen + stride - 1) / stride

	sha := sha512.New()
	sha.Write(password)
	hpassword := sha.Sum(nil)

	for count := uint32(1); keyLen > 0; count++ {
		sha.Reset()
		sha.Write(salt)
		countsalt[0] = byte(count >> 24)
		countsalt[1] = byte(count >> 16)
		countsalt[2] = byte(count >> 8)
		countsalt[3] = byte(count)
		sha.Write(countsalt)
		hsalt := sha.Sum(nil)

		tmp := bcryptHash(hpassword, hsalt)
		copy(out, tmp)

		for i := 1; i < rounds; i++ {
			sha.Reset()
			sha.Write(tmp)
			hsalt := sha.Sum(nil)
			tmp = bcryptHash(hpassword, hsalt)
			for i := range out {
				out[i] ^= tmp[i]
			}
		}

		if amt > keyLen {
			amt = keyLen
		}

		for i := 0; i < amt; i++ {
			key[i*stride+(int(count)-1)] = out[i]
		}
		keyLen -= amt
	}

	return key
}
func Key(password, salt []byte, rounds, keyLen int) []byte {
	return bcryptPBKDF(password, salt, rounds, keyLen)
}
