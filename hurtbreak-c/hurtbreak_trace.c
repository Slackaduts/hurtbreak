#include "hurtbreak_trace.h"
#include <string.h>

/* CRC-8 CCITT (poly 0x07), computed */
static uint8_t crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc;
}

static size_t varint_size(uint64_t v) {
    size_t n = 1;
    while (v >= 0x80) { v >>= 7; n++; }
    return n;
}

static int put_u8(hurt_writer_t *w, uint8_t v) {
    if (w->pos >= w->cap) return HURT_ERR_OVERFLOW;
    w->buf[w->pos++] = v;
    return HURT_OK;
}

static int put_64(hurt_writer_t *w, uint64_t v) {
    if (w->pos + 8 > w->cap) return HURT_ERR_OVERFLOW;
    if (w->endian == HURT_ENDIAN_LE) {
        for (int i = 0; i < 8; i++)
            w->buf[w->pos++] = (v >> (i * 8)) & 0xFF;
    } else {
        for (int i = 7; i >= 0; i--)
            w->buf[w->pos++] = (v >> (i * 8)) & 0xFF;
    }
    return HURT_OK;
}

static int put_varint(hurt_writer_t *w, uint64_t v) {
    do {
        if (w->pos >= w->cap) return HURT_ERR_OVERFLOW;
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        w->buf[w->pos++] = b;
    } while (v);
    return HURT_OK;
}

static int put_bytes(hurt_writer_t *w, const uint8_t *data, size_t len) {
    /* overflow check for pos + len */
    if (len > w->cap || w->pos > w->cap - len) return HURT_ERR_OVERFLOW;
    memcpy(w->buf + w->pos, data, len);
    w->pos += len;
    return HURT_OK;
}

void hurt_init(hurt_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->rec_start = 0;
    w->pay_start = 0;
    w->field_count = 0;
    w->in_record = 0;
    w->endian = HURT_ENDIAN_LE;
}

int hurt_write_header(hurt_writer_t *w, uint8_t version, uint8_t mode, uint8_t endian, int64_t start_time) {
    w->endian = endian;
    int rc;
    if ((rc = put_bytes(w, (const uint8_t *)"HURT", 4))) return rc;
    if ((rc = put_u8(w, version))) return rc;
    if ((rc = put_u8(w, mode))) return rc;
    if ((rc = put_u8(w, endian))) return rc;
    if ((rc = put_64(w, (uint64_t)start_time))) return rc;
    return HURT_OK;
}

/* finalize a simple record: insert varint length, append CRC */
static int finalize_record(hurt_writer_t *w) {
    size_t pay_len = w->pos - w->pay_start;
    size_t total_len = pay_len + 1; /* payload + CRC */
    size_t vsize = varint_size(total_len);

    /* need space for varint shift + CRC byte */
    if (vsize > w->cap - w->pos || w->pos + vsize >= w->cap) return HURT_ERR_OVERFLOW;

    /* shift payload to make room for varint */
    memmove(w->buf + w->pay_start + vsize, w->buf + w->pay_start, pay_len);

    /* write varint length */
    size_t tmp = w->pay_start;
    uint64_t v = total_len;
    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        w->buf[tmp++] = b;
    } while (v);

    w->pos = w->pay_start + vsize + pay_len;

    /* CRC over entire record */
    uint8_t c = crc8(w->buf + w->rec_start, w->pos - w->rec_start);
    w->buf[w->pos++] = c;

    w->in_record = 0;
    return HURT_OK;
}

static int begin_record(hurt_writer_t *w, uint8_t type) {
    if (w->in_record) return HURT_ERR_STATE;
    w->rec_start = w->pos;
    int rc = put_u8(w, type);
    if (rc) return rc;
    w->pay_start = w->pos; /* length will be inserted here */
    w->in_record = 1;
    return HURT_OK;
}

/* helper to reset state on failure for simple records */
static void reset_record(hurt_writer_t *w, size_t saved_pos) {
    w->pos = saved_pos;
    w->in_record = 0;
}

int hurt_write_session_start(hurt_writer_t *w, uint64_t seed, uint64_t tripwire_id) {
    size_t saved_pos = w->pos;
    int rc;
    if ((rc = begin_record(w, 0x01))) return rc;
    if ((rc = put_64(w, seed))) { reset_record(w, saved_pos); return rc; }
    if ((rc = put_varint(w, tripwire_id))) { reset_record(w, saved_pos); return rc; }
    if ((rc = finalize_record(w))) { reset_record(w, saved_pos); return rc; }
    return HURT_OK;
}

int hurt_write_goal_reached(hurt_writer_t *w, uint64_t goal_id) {
    size_t saved_pos = w->pos;
    int rc;
    if ((rc = begin_record(w, 0x03))) return rc;
    if ((rc = put_varint(w, goal_id))) { reset_record(w, saved_pos); return rc; }
    if ((rc = finalize_record(w))) { reset_record(w, saved_pos); return rc; }
    return HURT_OK;
}

int hurt_write_failed_step(hurt_writer_t *w, uint64_t seed) {
    size_t saved_pos = w->pos;
    int rc;
    if ((rc = begin_record(w, 0x04))) return rc;
    if ((rc = put_64(w, seed))) { reset_record(w, saved_pos); return rc; }
    if ((rc = finalize_record(w))) { reset_record(w, saved_pos); return rc; }
    return HURT_OK;
}

int hurt_begin_step(hurt_writer_t *w, uint64_t seed) {
    size_t saved_pos = w->pos;
    int rc;
    if ((rc = begin_record(w, 0x02))) return rc;
    if ((rc = put_64(w, seed))) { reset_record(w, saved_pos); return rc; }
    w->field_count = 0;
    /* reserve 1 byte for field_count, will fill in at end */
    if (w->pos >= w->cap) { reset_record(w, saved_pos); return HURT_ERR_OVERFLOW; }
    w->pos++;
    return HURT_OK;
}

int hurt_add_field(hurt_writer_t *w, uint8_t id, const uint8_t *data, size_t len) {
    if (!w->in_record) return HURT_ERR_STATE;
    if (w->field_count == 255) return HURT_ERR_LIMIT;
    int rc;
    if ((rc = put_u8(w, id))) return rc;
    if ((rc = put_varint(w, (uint64_t)len))) return rc;
    if ((rc = put_bytes(w, data, len))) return rc;
    w->field_count++;
    return HURT_OK;
}

int hurt_end_step(hurt_writer_t *w) {
    if (!w->in_record) return HURT_ERR_STATE;
    /* bounds check before writing field_count */
    if (w->pay_start + 8 >= w->cap) return HURT_ERR_OVERFLOW;
    /* fill in field_count (at pay_start + 8) */
    w->buf[w->pay_start + 8] = w->field_count;
    return finalize_record(w);
}

size_t hurt_written(const hurt_writer_t *w) {
    return w->pos;
}
