#include <yara.h>
#include <stdio.h>
#include <string.h>
#include "cgoyara.h"

size_t stream_read(void* ptr, size_t size, size_t count, void* user_data) {
	return cgo_stream_read(ptr, size, count, user_data);
}

size_t stream_write(const void* ptr, size_t size, size_t count, void* user_data) {
	return cgo_stream_write(ptr, size, count, user_data);
}

RESULT *yr_allocate_result() {
	RESULT *ptr = (RESULT *) malloc(sizeof(RESULT));
	memset(ptr, 0, sizeof(RESULT));
	return ptr;
}

int yr_callback(int msg, void* msg_data, void* user_data) {
	if (msg != CALLBACK_MSG_RULE_MATCHING) {
		return CALLBACK_CONTINUE;
	}

	RESULT *res = (RESULT *) user_data;
	YR_RULE *rule = (YR_RULE *) msg_data;

	// copy matching rule name, set last position to null byte
	strncpy(res->name, rule->identifier, YR_RULE_NAME);
	res->name[YR_RULE_NAME - 1] = '\0';

	return CALLBACK_ABORT;
}
