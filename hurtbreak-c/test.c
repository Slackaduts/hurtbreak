#include <stdio.h>
#include <stdint.h>
#include "hurtbreak_trace.h"

int main(void) {
    uint8_t buf[1024];
    hurt_writer_t w;

    hurt_init(&w, buf, sizeof(buf));
    hurt_write_header(&w, 0x01, 0x01, HURT_ENDIAN_LE, 1766371438000LL);
    hurt_write_session_start(&w, 0xDEADBEEF, 42);

    hurt_begin_step(&w, 0xCAFEBABE);
    uint8_t field0[] = {1, 2, 3, 4};
    uint8_t field1[] = {0xFF};
    hurt_add_field(&w, 0, field0, sizeof(field0));
    hurt_add_field(&w, 1, field1, sizeof(field1));
    hurt_end_step(&w);

    hurt_write_goal_reached(&w, 42);

    FILE *f = fopen("c_test.hurt", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(buf, 1, hurt_written(&w), f);
    fclose(f);

    printf("Wrote %zu bytes to test.hurt\n", hurt_written(&w));
    return 0;
}
