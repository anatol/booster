package main

func MemZeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
