#ifndef _CGO_YARA
#define _CGO_YARA

#define YR_INFECTED 1
#define YR_RULE_NAME 512

typedef struct result {
	char name[YR_RULE_NAME];
} RESULT;

RESULT *yr_allocate_result();
int yr_callback(int msg, void* msg_data, void* user_data);

// stream functions
size_t stream_read(void* ptr, size_t size, size_t count, void* user_data);
size_t stream_write(const void* ptr, size_t size, size_t count, void* user_data);

#endif
