#ifndef TEST_CONFIG_H
#define TEST_CONFIG_H
#include <stdbool.h>

#define FILE_SIZE_MAX    (1 << 30)
#define FILE_SIZE_MIN    (1 << 30)

#define BLOCK_SIZE_MAX   (8 << 10)
#define BLOCK_SIZE_MIN   (8 << 10)

#define FILE_COUNT_MAX   8
#define FILE_COUNT_MIN   8

#define REQ_COUNT_MAX    18
#define REQ_COUNT_MIN    18
#define REQ_USE_OP_LIST  1
int op_list[REQ_COUNT_MAX] = {0, 1, 2,
							  0, 2, 1,
							  1, 0, 2,
							  1, 2, 0,
							  2, 0, 1,
							  2, 1, 0};

#define REQ_UNIQUE_RANGE 0

#define BASE_PATTERN_BYTE 65
#define WRITE_PATTERN_BYTE 66

#endif
