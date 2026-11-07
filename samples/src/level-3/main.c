/*
 * Sample: Level 3 - Lookup Transform.
 * Purpose: table-driven byte substitution and a loop; useful for observing
 *          lookup tables and optimized loops.
 * Input: a fixed in-memory byte array. Output: process exit code.
 * Safety: compiled only; the workbench never executes this file.
 */
#include <stddef.h>
#include <stdint.h>

static const uint8_t SUBSTITUTION[16] = {
    0x6u, 0x4u, 0xcu, 0x5u, 0x0u, 0x7u, 0x2u, 0xeu,
    0x1u, 0xfu, 0x3u, 0xdu, 0x8u, 0xau, 0x9u, 0xbu
};

static uint8_t transform_byte(uint8_t value, size_t position) {
    uint8_t high = SUBSTITUTION[(value >> 4u) & 0x0fu];
    uint8_t low = SUBSTITUTION[value & 0x0fu];
    return (uint8_t)((high << 4u) | low) ^ (uint8_t)(position * 13u);
}

uint32_t transform_score(const uint8_t *data, size_t length) {
    uint32_t total = 0x13579bdfu;
    for (size_t i = 0; i < length; ++i) {
        total = (total << 3u) | (total >> 29u);
        total ^= transform_byte(data[i], i);
    }
    return total;
}

int main(void) {
    static const uint8_t sample[] = {0x21u, 0x43u, 0x65u, 0x87u};
    return (int)(transform_score(sample, sizeof sample) & 0xffu);
}
