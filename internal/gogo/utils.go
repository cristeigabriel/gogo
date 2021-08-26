package gogo

//	for interacting with C strings
func strlen(str []uint8) int {
	strlen := 0
	arrayLength := len(str)

	for i := 0; i < arrayLength; i++ {
		if str[i] == 0 || i == arrayLength {
			strlen = i
			break
		}
	}

	return strlen
}

func stringify(str []uint8) string {
	nullTerminator := strlen(str)
	return string(str[:nullTerminator])
}
