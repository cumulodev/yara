#ifndef _CGO_YARA
#define _CGO_YARA
int callback(int msg, void* msg_data, void* user_data);
void translate_rule(void* go, YR_RULE* c);
#endif
