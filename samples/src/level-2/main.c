/*
 * Sample: Level 2 - Tiered Score.
 * Purpose: helpers, branches, a switch and named constants for disassembly
 *          and decompiler exercises.
 * Input: none. Output: process exit code derived from a fixed score/tier.
 * Safety: compiled only; the workbench never executes this file.
 */
#include <stdint.h>

static const uint32_t BASE_SCORE = 120u;

static uint32_t tier_bonus(uint32_t tier) {
    switch (tier) {
        case 1u: return 5u;
        case 2u: return 15u;
        case 3u: return 30u;
        default: return 0u;
    }
}

static uint32_t apply_threshold(uint32_t score) {
    if (score >= 200u) return score + 12u;
    if (score >= 100u) return score + 4u;
    return score;
}

uint32_t calculate_badge_score(uint32_t points, uint32_t tier) {
    return apply_threshold(BASE_SCORE + points + tier_bonus(tier));
}

int main(void) {
    return (int)(calculate_badge_score(31u, 2u) & 0xffu);
}
