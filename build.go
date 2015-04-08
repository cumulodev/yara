package yara

/*
#cgo pkg-config: yara

#include <yara.h>

const char* cgo_rule_identifier(YR_RULE* rule) {
	return rule->identifier;
}
*/
import "C"
