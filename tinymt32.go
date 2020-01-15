// Package tinymt32 provides TinyMT32 Pseudorandom Number Generator (PRNG)
// specified in RFC 8682 https://www.rfc-editor.org/rfc/rfc8682.html
package tinymt32

const (
	mat1 = 0x8f7011ee
	mat2 = 0xfc78ff1f
	tmat = 0x3793fdff
)

// A Source represents a source of uniformly-distributed pseudo-random uint32 values in the range [0, 1<<32).
type Source struct {
	status [4]uint32
	mat1   uint32
	mat2   uint32
	tmat   uint32
}

// NewSource returns a new pseudo-random Source seeded with the given value. This source is not safe for concurrent use by multiple goroutines.
func NewSource(seed uint32) *Source {
	const minLoop = 8
	const preLoop = 8

	r := &Source{
		status: [...]uint32{seed, mat1, mat2, tmat},
		mat1:   mat1,
		mat2:   mat2,
		tmat:   tmat,
	}

	for i := uint32(1); i < minLoop; i++ {
		r.status[i&3] ^= i + 1812433253*(r.status[(i-1)&3]^(r.status[(i-1)&3]>>30))
	}

	/*
	 * NB: The parameter set of this specification warrants
	 * that none of the possible 2^^32 seeds leads to an
	 * all-zero 127-bit internal state. Therefore, the
	 * period_certification() function of the original
	 * TinyMT32 source code has been safely removed. If
	 * another parameter set is used, this function will
	 * have to be reintroduced here.
	 */
	for i := 0; i < preLoop; i++ {
		r.nextState()
	}

	return r
}

// Uint32 returns a non-negative pseudo-random 32-bit integer as an uint32.
func (r *Source) Uint32() uint32 {
	r.nextState()
	return r.temper()
}

// Internal tinymt32 constants.
const (
	sh0  = 1
	sh1  = 10
	sh8  = 8
	mask = 0x7fffffff
)

func (r *Source) nextState() {
	y := r.status[3]
	x := (r.status[0] & mask) ^ r.status[1] ^ r.status[2]
	x ^= (x << sh0)
	y ^= (y >> sh0) ^ x
	r.status[0] = r.status[1]
	r.status[1] = r.status[2]
	r.status[2] = x ^ (y << sh1)
	r.status[3] = y
	/*
	 * The if (y & 1) {...} block below replaces:
	 *     r.status[1] ^= -((int32_t)(y & 1)) & r.mat1;
	 *     r.status[2] ^= -((int32_t)(y & 1)) & r.mat2;
	 * The adopted code is equivalent to the original code
	 * but does not depend on the representation of negative
	 * integers by 2's complements. It is therefore more
	 * portable but includes an if branch, which may slow
	 * down the generation speed.
	 */
	if y&1 != 0 {
		r.status[1] ^= r.mat1
		r.status[2] ^= r.mat2
	}
}

func (r *Source) temper() uint32 {
	t0 := r.status[3]
	t1 := r.status[0] + (r.status[2] >> sh8)
	t0 ^= t1
	/*
	 * The if (t1 & 1) {...} block below replaces:
	 *     t0 ^= -((int32_t)(t1 & 1)) & r.tmat;
	 * The adopted code is equivalent to the original code
	 * but does not depend on the representation of negative
	 * integers by 2's complements. It is therefore more
	 * portable but includes an if branch, which may slow
	 * down the generation speed.
	 */
	if t1&1 != 0 {
		t0 ^= r.tmat
	}
	return t0
}
