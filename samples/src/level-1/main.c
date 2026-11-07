/*
 * Sample: Level 1 - Badge Math.
 * Purpose: one small arithmetic routine; useful for ELF headers, symbols and
 *          a single readable constant.
 * Input: none. Output: process exit code derived from badge_value(42).
 * Safety: compiled only; the workbench never executes this file.
 */
#include <stdint.h>

static const uint32_t OFFSET = 37u;

uint32_t badge_value(uint32_t input) {
    return (input * 17u + OFFSET) % 1009u;
}

int main(void) {
    return (int)(badge_value(42u) & 0xffu);
}
