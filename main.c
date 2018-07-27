#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "test_config.h"

#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#define MIN(a, b) ((a < b) ? a : b)
#define rand_range(min, max) ((rand() % (max - min + 1)) + min)



#define ERR_EXIT(s, fmt, attr...)						\
	do {											\
	    printf("ERROR %d: " fmt, errno, ##attr);	\
	    test_exit(s);								\
	} while (0)

#define LOG_FAIL(cnt, fmt, attr...)				\
	do {										\
	    printf("FAIL: " fmt, ##attr);			\
		cnt++;									\
	} while (0)


#define OP_READ    0
#define OP_WRITE   1
#define OP_DISCARD 2

#define BM_BIT_CLEAR  0
#define BM_BIT_SET    1

struct range {
	uint64_t start;
	uint64_t len;
	uint64_t minlen;
};

struct request {
    int op;
	struct range range;
	uint8_t *buf;
};

struct test_file {
	int fd;
    int bitmap;

	uint64_t file_size;
	uint64_t block_size;
	uint64_t blocks_per_file;
	uint64_t invalid_blocks;

	char *base_pattern;
	char *write_pattern;

	uint64_t reqs_len;
	struct request *reqs;
};

struct test_state {
	uint64_t files_len;
	struct test_file *files;
	uint64_t invalid_files;

};

int fallocate(int fd, int mode, off_t offset, off_t len);
static void test_exit(struct test_state *s);

static inline char
write_bit(char byte, char bit, char value)
{
	char mask;
	mask = 1 << bit;
	if (value)
		return (byte | mask);
	else
		return (byte & ~mask);
}

static inline uint8_t
read_bitmap(struct test_state *s, int fd, uint64_t blk)
{
	int err;
	uint64_t offset;
	uint8_t bitmap, bit;

	offset = blk / 8;
	bit = blk % 8;

	lseek(fd, offset, SEEK_SET);
	read(fd, &bitmap, sizeof(uint8_t));
	if (errno) {
		ERR_EXIT(s, "failed to read bitmap\n");
		return err;
	}
	if (bitmap & (1 << bit))
		return BM_BIT_SET;
	else
		return BM_BIT_CLEAR;
}

static inline int
write_bitmap(struct test_state *s, int fd, uint64_t blk, uint8_t value)
{
	int err;
	uint64_t offset;
	uint8_t bit, bitmap;

	offset = blk / 8;
	bit = blk % 8;

    lseek(fd, offset, SEEK_SET);
	read(fd, &bitmap, sizeof(uint8_t));
	if (errno) {
		ERR_EXIT(s, "failed to read bitmap\n");
	}
	bitmap = write_bit(bitmap, bit, value);

	lseek(fd, offset, SEEK_SET);
	write(fd, &bitmap, sizeof(uint8_t));
	if (errno) {
		ERR_EXIT(s, "failed to write bitmap\n");
	}

	return 0;
}

static inline int
cmpblk(char *b1, char *b2, uint64_t block_size)
{
	int i;
	int c1 = 0, c2 = 0;
	if (b2 == NULL) {
		int sum = 0;
		for (i = 0; i < block_size; i++)
			sum |= b1[i];
		if (sum)
			return 1;
		else
			return 0;
	} else {
		if (memcmp(b1, b2, block_size))
			return 1;
		else
			return 0;
	}
}

static int
validate_block(struct test_state *s, struct test_file *f, uint64_t blk)
{
	uint64_t offset;
	char buf[f->block_size];

	offset = blk * f->block_size;
	lseek(f->fd, offset, SEEK_SET);
	read(f->fd, buf, f->block_size);
	if (errno)
		ERR_EXIT(s, "validate block: failed to read block\n");

	if (read_bitmap(s, f->bitmap, blk)) {    // if block has data
		return ((cmpblk(buf, f->base_pattern, f->block_size)) &&
				(cmpblk(buf, f->write_pattern, f->block_size)));
	} else {                             // if block has been discarded
		return (cmpblk(buf, NULL, f->block_size));
	}
}

static uint64_t
validate_file(struct test_state *s, struct test_file *f)
{
	uint64_t blk;

	for (blk = 0; blk < f->blocks_per_file; blk++) {
		if (validate_block(s, f, blk)) {
			LOG_FAIL(f->invalid_blocks, "failed to validate blk %lu\n", blk);
		}
	}

	return f->invalid_blocks;
}

static uint64_t
validate_files(struct test_state *s)
{
	int i;
	printf("validating files\n");
	for (i = 0; i < s->files_len; i++) {
		if (validate_file(s, &s->files[i])) {
			LOG_FAIL(s->invalid_files, "file %d is invalid\n", i);
		}
	}

	return s->invalid_files;
}


static void
do_discard_request(struct test_state *s, struct test_file f, struct request req)
{
	int err, fd, mode;
	uint64_t offset, length, blk;

	printf("do discard\n");

	fd = f.fd;
	mode = FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE;
	offset = req.range.start;
	length = req.range.len;

	err = fallocate(fd, mode, offset, length);
	if (err)
	    ERR_EXIT(s, "failed to deallocate memory range\n");

	err = ioctl(fd, FITRIM, &req.range);
	if (errno)
		ERR_EXIT(s, "FITRIM ioctl failed\n");

	blk = offset / f.block_size;
	write_bitmap(s, f.bitmap, blk, 0);
}

static void
do_write_request(struct test_state *s, struct test_file f, struct request req)
{
	uint64_t blk, offset;

	printf("do write request\n");

	offset = req.range.start;

	lseek(f.fd, offset, SEEK_SET);
	write(f.fd, f.write_pattern, req.range.len);
	if (errno)
		ERR_EXIT(s, "failed write request");

	blk = offset / f.block_size;
	write_bitmap(s, f.bitmap, blk, 1);
}

static void
do_read_request(struct test_state *s, struct test_file f, struct request req)
{
	int err;
	uint64_t blk, offset;

	printf("do read request %p\n", req.buf);

	offset = req.range.start;

	lseek(f.fd, offset, SEEK_SET);
	err = read(f.fd, req.buf, req.range.len);
	if (errno)
		ERR_EXIT(s, "read request failed\n");
}

static void
do_requests(struct test_state *s, struct test_file f)
{
	int i, n;
	for (i = 0; i < f.reqs_len; i++) {
		struct request req = f.reqs[i];
		switch (req.op) {
		case OP_READ:
			do_read_request(s, f, req);
			break;
		case OP_WRITE:
			do_write_request(s, f, req);
			break;
		case OP_DISCARD:
			do_discard_request(s, f, req);
			break;
		}
		/*
	    if ((i + 1) % 3 == 0)
			validate_files(s);
		*/
	}
}

static void
write_base_pattern(struct test_state *s, struct test_file f)
{
	uint64_t blk, blks_per_byte;

	blks_per_byte = f.blocks_per_file / 8;
	for (blk = 0; blk < blks_per_byte; blk++) {
		char c = 0xFF;
		write(f.bitmap, &c, sizeof(char));
		if (errno)
			ERR_EXIT(s, "failed to initialize bitmap\n");
	}

	for (blk = 0; blk < f.blocks_per_file; blk++) {
		write(f.fd, f.base_pattern, f.block_size);
		if (errno)
			ERR_EXIT(s, "failed to write base pattern to block\n");
	}
}

static struct range
init_range(struct test_state *s, struct test_file f)
{
	static struct range range;
	struct range r;
	static int static_range_set = 0;
	uint64_t start_blk;

	if (static_range_set)
		return range;

	start_blk = rand() % f.blocks_per_file;
	r.start = start_blk * f.block_size;
	r.len = f.block_size;
	r.minlen = f.block_size;

	if (!REQ_UNIQUE_RANGE) {
		range = r;
		static_range_set = 1;
	}

	return r;
}

static struct request
init_request(struct test_state *s, struct test_file f, int op)
{
	struct request req;

	if (!REQ_USE_OP_LIST)
		req.op = rand() % 3;
	else
		req.op = op;

	if (req.op == OP_READ ||
		req.op == OP_WRITE) {
		req.buf = calloc(f.block_size, sizeof(char));
		if (!req.buf)
			ERR_EXIT(s, "failed to allocate request buffer\n");
	}
	req.range = init_range(s, f);

	return req;
}

static void
free_request(struct request *r)
{
	if (r->op != OP_DISCARD)
		free(r->buf);
}

static struct request *
init_requests(struct test_state *s, struct test_file f)
{
	uint64_t i;
	struct request *reqs = NULL;

	reqs = calloc(f.reqs_len, sizeof(struct request));
	if (!reqs)
		ERR_EXIT(s, "failed to allocate requests\n");

	for (i = 0; i < f.reqs_len; i++) {
		reqs[i] = init_request(s, f, op_list[i]);

	}

	return reqs;
}

static void
free_requests(struct request *reqs, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; i++)
		free_request(&reqs[i]);


	free(reqs);
}

static char *
init_pattern(struct test_state *s, struct test_file f, char pattern_byte)
{
	uint64_t i;
	char *pattern = NULL;

	pattern = calloc(f.block_size, sizeof(char));
	if (!pattern)
		ERR_EXIT(s, "failed to allocate base pattern\n");

	for (i = 0; i < f.block_size; i++) {
		pattern[i] = pattern_byte;
	}

	return pattern;
}

static struct test_file
init_test_file(struct test_state *s)
{
	struct test_file f;

	f.fd = open(".", O_TMPFILE|O_RDWR);
	if (!f.fd)
		ERR_EXIT(s, "failed to open test file\n");

	f.bitmap = open(".", O_TMPFILE|O_RDWR);
	if (!f.bitmap)
		ERR_EXIT(s, "failed to open bitmap file\n");

	f.file_size = rand_range(FILE_SIZE_MIN, FILE_SIZE_MAX);
	f.block_size = rand_range(BLOCK_SIZE_MIN, BLOCK_SIZE_MAX);
	f.blocks_per_file = f.file_size / f.block_size;
	f.reqs_len = rand_range(REQ_COUNT_MIN, REQ_COUNT_MAX);

	f.base_pattern = init_pattern(s, f, BASE_PATTERN_BYTE);
	f.write_pattern = init_pattern(s, f, WRITE_PATTERN_BYTE);
	f.reqs = init_requests(s, f);

	write_base_pattern(s, f);
	return f;
}

static void
free_test_file(struct test_file *f)
{
	close(f->fd);
	close(f->bitmap);

	free(f->base_pattern);
	free(f->write_pattern);

	free_requests(f->reqs, f->reqs_len);
}

static struct test_state *
init_test_state()
{
	int i;
	struct test_state *s = NULL;
	printf("init test state\n");
	s = calloc(1, sizeof(struct test_state));
	if (!s)
		ERR_EXIT(s, "failed to allocate test state\n");

	s->files_len = rand_range(FILE_COUNT_MIN, FILE_COUNT_MAX);
	s->files = calloc(s->files_len, sizeof(struct test_file));
	if (!s->files)
		ERR_EXIT(s, "failed to allocate test files\n");

	for (i = 0; i < s->files_len; i++) {
		printf("Initializing file %lu/%lu\n", i+1, s->files_len);
		s->files[i] = init_test_file(s);
	}
	return s;
}

static void
free_test_state(struct test_state *s)
{
	uint64_t i;

	for (i = 0; i < s->files_len; i++)
		free_test_file(&s->files[i]);
	free(s->files);
	free(s);
}

static void
test_exit(struct test_state *s)
{
	free_test_state(s);
	exit(0);
}

static void
print_test_results(struct test_state *s)
{
	uint64_t i;

	printf("Total files: %lu\n", s->files_len);
	printf("Files corrupted: %lu\n", s->invalid_files);
	for (i = 0; i < s->files_len; i++) {
		struct test_file f;
		f = s->files[i];

		printf("File %lu:\n", i);
		printf("size: %lu\n", f.file_size);
		printf("block size: %lu\n", f.block_size);
		printf("blocks per file: %lu\n", f.blocks_per_file);
		printf("blocks corrupted: %lu\n", f.invalid_blocks);
	}

}

int
main(int argc, char **argv)
{
	int i;
	struct test_state *s = NULL;
	srand(time(0));

	s = init_test_state();

	for (i = 0; i < s->files_len; i++) {
		do_requests(s, s->files[i]);
	}
	validate_files(s);
	print_test_results(s);

	free_test_state(s);
}
