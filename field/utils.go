package field

import "strconv"

func FormatWithUnderscores(n int64) string {
	// Convert number to string
	str := strconv.FormatInt(n, 10)

	// Handle numbers with less than 4 digits
	if len(str) < 4 {
		return str
	}

	// Start from the end and work backwards
	var result []byte
	for i := 0; i < len(str); i++ {
		// Add underscore before every 3rd digit from the right, but not at the start
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, '_')
		}
		result = append(result, str[i])
	}

	return string(result)
}
