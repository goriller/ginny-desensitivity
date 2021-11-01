package desensitivity

// 默认配置
var defaultOptions = &Options{
	tag:        "ENC", // 密文标识符
	step:       "@",   // 分隔符
	encryptKey: "fc1c095e",
}

// Options
type Options struct {
	tag        string
	step       string
	encryptKey string
	encryptFn  EncryptFunc
	decryptFn  DecryptFunc
}

// Optional
type Optional func(s *Options)

// EncryptFunc
type EncryptFunc func(field string, opt *Options) (string, error)

// DecryptFunc
type DecryptFunc func(field string, opt *Options) (string, error)

// GetOption
func GetOption(opts ...Optional) *Options {
	option := &Options{
		tag:        defaultOptions.tag,
		step:       defaultOptions.step,
		encryptKey: defaultOptions.encryptKey,
		encryptFn:  aesEncrypt,
		decryptFn:  aesDecrypt,
	}
	if len(opts) > 0 {
		for _, o := range opts {
			o(option)
		}
	}
	if option.step == "" {
		option.step = defaultOptions.step
	}
	return option
}

// getDefaultOption
func getDefaultOption(opt ...*Options) *Options {
	option := defaultOptions
	if len(opt) > 0 {
		option = opt[0]
	}
	if option.encryptFn == nil {
		option.encryptFn = aesEncrypt
	}
	if option.decryptFn == nil {
		option.decryptFn = aesDecrypt
	}
	if option.step == "" {
		option.step = defaultOptions.step
	}
	return option
}

// WithTag
func WithTag(p string) Optional {
	return func(s *Options) {
		s.tag = p
	}
}

// WithStep
func WithStep(p string) Optional {
	return func(s *Options) {
		s.step = p
	}
}

// WithEncryptKey
func WithEncryptKey(p string) Optional {
	return func(s *Options) {
		s.encryptKey = p
	}
}

// WithEncryptFunc
func WithEncryptFunc(f EncryptFunc) Optional {
	return func(s *Options) {
		s.encryptFn = aesEncrypt
		if f != nil {
			s.encryptFn = f
		}
	}
}

// WithDecryptFunc
func WithDecryptFunc(f DecryptFunc) Optional {
	return func(s *Options) {
		s.decryptFn = aesDecrypt
		if f != nil {
			s.decryptFn = f
		}
	}
}
