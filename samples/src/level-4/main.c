/*
 * Sample: Level 4 - Record Decoder.
 * Purpose: a tiny in-memory record parser with bounds checks and a checksum;
 *          no file or network I/O.
 * Input: a fixed byte array. Output: process exit code.
 * Safety: compiled only; the workbench never executes this file.
 */
#include <stddef.h>
#include <stdint.h>

struct record_view {
    uint8_t version;
    uint8_t kind;
    uint16_t length;
    const uint8_t *payload;
};

static uint16_t read_u16_be(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static int decode_record(const uint8_t *bytes, size_t available, struct record_view *out) {
    if (bytes == NULL || out == NULL || available < 6u) return 0;
    if (bytes[0] != 0x52u || bytes[1] != 0x53u) return 0;
    out->version = bytes[2];
    out->kind = bytes[3];
    out->length = read_u16_be(bytes + 4u);
    if (available < (size_t)out->length + 6u) return 0;
    out->payload = bytes + 6u;
    return 1;
}

static uint32_t checksum_record(const struct record_view *record) {
    uint32_t checksum = 0x811c9dc5u ^ record->version ^ ((uint32_t)record->kind << 8u);
    for (uint16_t i = 0; i < record->length; ++i) {
        checksum ^= record->payload[i];
        checksum *= 0x01000193u;
    }
    return checksum;
}

int main(void) {
    static const uint8_t sample[] = {0x52u, 0x53u, 1u, 2u, 0u, 3u, 'a', 'b', 'c'};
    struct record_view record = {0};
    if (!decode_record(sample, sizeof sample, &record)) return 1;
    return (int)(checksum_record(&record) & 0xffu);
}
