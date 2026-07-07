package sign

import "errors"

// ErrUnsupportedKeyType is returned when the signing key is neither an EC P-384
// key nor an RSA-4096 key. The CLI maps it to exit code 2 (spec §2).
var ErrUnsupportedKeyType = errors.New("unsupported key type")
