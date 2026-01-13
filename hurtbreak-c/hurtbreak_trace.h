#ifndef HURTBREAK_TRACE_H
#define HURTBREAK_TRACE_H

#include <stdint.h>
#include <stddef.h>

#define HURT_OK           0
#define HURT_ERR_OVERFLOW 1
#define HURT_ERR_STATE    2
#define HURT_ERR_LIMIT    3  /* field count exceeded */

#define HURT_ENDIAN_LE    0
#define HURT_ENDIAN_BE    1

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
    size_t rec_start;   /* record start position */
    size_t pay_start;   /* payload start position */
    uint8_t field_count;
    uint8_t in_record;
    uint8_t endian;
} hurt_writer_t;

void hurt_init(hurt_writer_t *w, uint8_t *buf, size_t cap);
int  hurt_write_header(hurt_writer_t *w, uint8_t version, uint8_t mode, uint8_t endian, int64_t start_time);

int  hurt_write_session_start(hurt_writer_t *w, uint64_t seed, uint64_t tripwire_id);
int  hurt_write_goal_reached(hurt_writer_t *w, uint64_t goal_id);
int  hurt_write_failed_step(hurt_writer_t *w, uint64_t seed);

int  hurt_begin_step(hurt_writer_t *w, uint64_t seed);
int  hurt_add_field(hurt_writer_t *w, uint8_t id, const uint8_t *data, size_t len);
int  hurt_end_step(hurt_writer_t *w);

size_t hurt_written(const hurt_writer_t *w);

#endif
