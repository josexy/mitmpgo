package mitmpgo

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"math/rand"
	"time"

	"github.com/josexy/mitmpgo/internal/cache"
	"github.com/josexy/mitmpgo/internal/cert"
)

var errNoPriKey = errors.New("no private key available")

type priKeyPool struct {
	rand *rand.Rand
	keys []*rsa.PrivateKey
}

func newPriKeyPool(maxSize int) *priKeyPool {
	if maxSize <= 0 {
		maxSize = 10
	}
	pool := &priKeyPool{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
		keys: make([]*rsa.PrivateKey, 0, maxSize),
	}
	return pool
}

func (p *priKeyPool) Get() (*rsa.PrivateKey, error) {
	var n, m = len(p.keys), cap(p.keys)
	if m == 0 {
		return nil, errNoPriKey
	}
	if n < m {
		key, err := cert.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		p.keys = append(p.keys, key)
		return key, nil
	}
	index := p.rand.Intn(n)
	key := p.keys[index]
	return key, nil
}

type certPool struct {
	cache.Cache[string, tls.Certificate]
}

func newCertPool(maxCapacity int, checkInterval, certExpiredSecond time.Duration) *certPool {
	if maxCapacity <= 0 {
		maxCapacity = 100
	}
	if checkInterval <= 0 {
		checkInterval = time.Second * 30
	}
	if certExpiredSecond <= 0 {
		certExpiredSecond = time.Second * 15
	}
	return &certPool{
		Cache: cache.New[string, tls.Certificate](
			cache.WithMaxSize(maxCapacity),
			cache.WithInterval(checkInterval),
			cache.WithExpiration(certExpiredSecond),
			cache.WithBackgroundCheckCache(),
			cache.WithUpdateCacheExpirationOnGet(),
			// cache.WithDeleteExpiredCacheOnGet(),
		),
	}
}
