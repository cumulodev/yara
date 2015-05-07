rule metadata {
	meta:
		string = "abcdef"
		t      = true
		f      = false
		one    = 1
		two    = 2
	
	strings:
		$ = "metadata"

	condition:
		any of them
}
