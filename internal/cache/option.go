package cache

import "time"

type options struct {
	capacity                   int
	expiration                 time.Duration
	bgCheckInterval            time.Duration
	evictFn                    EvictCallback
	deleteExpiredCacheOnGet    bool
	updateCacheExpirationOnGet bool
	timeUnixNanoFn             func() int64
}

type Option interface{ apply(*options) }

type OptionFunc func(o *options)

func (f OptionFunc) apply(o *options) { f(o) }

func WithStdGoTimeUnixNano() Option {
	return OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return time.Now().UnixNano() } })
}

func WithCapacity(capacity int) Option {
	return OptionFunc(func(o *options) { o.capacity = capacity })
}

func WithExpiration(expiration time.Duration) Option {
	return OptionFunc(func(o *options) { o.expiration = expiration })
}

func WithEvictCallback(fn EvictCallback) Option {
	return OptionFunc(func(o *options) { o.evictFn = fn })
}

func WithUpdateCacheExpirationOnGet() Option {
	return OptionFunc(func(o *options) { o.updateCacheExpirationOnGet = true })
}

func WithDeleteExpiredCacheOnGet() Option {
	return OptionFunc(func(o *options) { o.deleteExpiredCacheOnGet = true })
}

func WithBackgroundCheckInterval(interval time.Duration) Option {
	return OptionFunc(func(o *options) { o.bgCheckInterval = interval })
}

func newOptions(opt ...Option) *options {
	options := &options{}
	for _, opt := range opt {
		opt.apply(options)
	}
	if options.capacity <= 0 {
		options.capacity = 2048
	}
	if options.expiration <= 0 {
		options.expiration = 15 * time.Second
	}
	return options
}
