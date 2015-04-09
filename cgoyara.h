#ifndef _CGO_YARA
#define _CGO_YARA

// exported go functions
int cgo_callback(int msg, void* msg_data, void* user_data);

// rule translation
void cgo_rule_set_identifier(void* rule, char* identifier);
void cgo_rule_add_tag(void* rule, char* tag);
void cgo_rule_add_metadata(void* rule, char* key, char* value);

// helper functions
int translate_rule(void* go, YR_RULE* c);
size_t stream_read(void* ptr, size_t size, size_t count, void* user_data);
size_t stream_write(const void* ptr, size_t size, size_t count, void* user_data);

#endif
