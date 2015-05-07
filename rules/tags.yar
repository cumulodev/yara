rule tags : lol rofl
{
	strings:
		$ = "tags"

	condition:
		any of them
}
