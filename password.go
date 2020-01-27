package splunk

import (
	"github.com/sethvargo/go-password/password"
)

type PasswordSpec struct {
	Length      int  `json:"length" structs:"length"`
	NumDigits   int  `json:"num_digits" structs:"num_digits"`
	NumSymbols  int  `json:"num_symbols" structs:"num_symbols"`
	AllowUpper  bool `json:"allow_upper" structs:"allow_upper"`
	AllowRepeat bool `json:"allow_repeat" structs:"allow_repeat"`
}

func DefaultPasswordSpec() *PasswordSpec {
	return &PasswordSpec{
		Length:      32,
		NumDigits:   4,
		NumSymbols:  4,
		AllowUpper:  true,
		AllowRepeat: true,
	}
}

func GeneratePassword(spec *PasswordSpec) (string, error) {
	passwdgen, err := password.NewGenerator(&password.GeneratorInput{
		LowerLetters: password.LowerLetters,
		UpperLetters: password.UpperLetters,
		Digits:       password.Digits,
		Symbols:      "_&^%$#@!", // mostly shell-safe set, TE-101
	})
	if err != nil {
		return "", err
	}

	if spec == nil {
		spec = DefaultPasswordSpec()
	}
	return passwdgen.Generate(spec.Length, spec.NumDigits, spec.NumSymbols, !spec.AllowUpper, spec.AllowRepeat)
}
