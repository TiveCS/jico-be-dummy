package validators

import (
	"regexp"
)

func IsValidEmail(email string) bool {
	// Email validation regular expression
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{3,}$`

	// Compile the regular expression
	regex := regexp.MustCompile(emailRegex)

	// Check if the email matches the regular expression
	return regex.MatchString(email)
}

func IsValidPassword(password string) bool {
	// Password validation regular expressions
	uppercaseRegex := `[A-Z]`
	lowercaseRegex := `[a-z]`
	digitRegex := `[0-9]`
	specialCharRegex := `[^A-Za-z0-9]`
	lengthRegex := `.{6,10}`

	// Compile the regular expressions
	uppercase := regexp.MustCompile(uppercaseRegex)
	lowercase := regexp.MustCompile(lowercaseRegex)
	digit := regexp.MustCompile(digitRegex)
	specialChar := regexp.MustCompile(specialCharRegex)
	length := regexp.MustCompile(lengthRegex)

	// Check if the password satisfies all conditions
	return uppercase.MatchString(password) &&
		lowercase.MatchString(password) &&
		digit.MatchString(password) &&
		specialChar.MatchString(password) &&
		length.MatchString(password)
}

func IsValidUsername(username string) bool {
	// Username validation regular expression
	usernameRegex := `^[A-Za-z0-9 ]{5,15}$`

	// Compile the regular expression
	regex := regexp.MustCompile(usernameRegex)

	// Check if the username matches the regular expression

	return regex.MatchString(username)
}
