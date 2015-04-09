#include <yara.h>
#include "cgoyara.h"

//void cgo_rule_set_identifier(void* rule, char* identifier);
//void cgo_rule_add_tag(void* rule, char* tag);

int translate_rule(void* go, YR_RULE* c) {
	const char* tag;
	YR_META* meta;

	cgo_rule_set_identifier(go, (char *)c->identifier);

	yr_rule_tags_foreach(c, tag) {
		cgo_rule_add_tag(go, (char *)tag);
	}

	yr_rule_metas_foreach(c, meta) {
		cgo_rule_add_metadata(go, (char *)meta->identifier, (char *)meta->string);
	}
}

size_t stream_read(void* ptr, size_t size, size_t count, void* user_data) {
	return cgo_stream_read(ptr, size, count, user_data);
}

size_t stream_write(const void* ptr, size_t size, size_t count, void* user_data) {
	return cgo_stream_write(ptr, size, count, user_data);
}
