package utils

import "regexp"

// RegexMatch returns true if str matches the given regex pattern.
func RegexMatch(pattern, str string) (bool, error) {
	reg, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return reg.MatchString(str), nil
}
