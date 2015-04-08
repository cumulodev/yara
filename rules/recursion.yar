rule First
{
	strings:
		$ = "rule"

	condition:
		1 of them
}

rule Second 
{
	strings:
		$ = "condition"

	condition:
		1 of them
}
