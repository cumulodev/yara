#include <yara.h>
#include <stdio.h>
#include <string.h>
#include "cgo.h"
#include "_cgo_export.h"

int callback(int msg, void* msg_data, void* user_data) {
	if (msg != CALLBACK_MSG_RULE_MATCHING) {
		return CALLBACK_CONTINUE;
	}

	return goCallback(user_data, (YR_RULE *) msg_data);
}

void translate_rule(void* go, YR_RULE* c) {
	goRuleSetIdentifier(go, (char *)c->identifier);

	const char* tag;
	yr_rule_tags_foreach(c, tag) {
		goRuleAddTag(go, (char *)tag);
	}

	YR_META* meta;
	yr_rule_metas_foreach(c, meta) {
		goRuleAddMetadata(go, (char *)meta->identifier, (char *)meta->string);
	}
}
