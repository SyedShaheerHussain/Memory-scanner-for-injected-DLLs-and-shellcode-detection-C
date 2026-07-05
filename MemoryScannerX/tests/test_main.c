/*
 * MemoryScannerX - minimal unit test harness.
 * Kept dependency-free (no GoogleTest) so the whole project builds with
 * only a C compiler + CMake, per the "no limit / smooth build" goal.
 * A GoogleTest-based suite can be swapped in later (see docs/).
 */
#include "utils/msx_entropy.h"
#include "utils/msx_sha256.h"
#include "scanner/msx_scoring.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

static int g_failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  [FAIL] %s\n", msg); g_failures++; } \
    else { printf("  [PASS] %s\n", msg); } \
} while (0)

static void test_entropy(void) {
    printf("test_entropy:\n");
    uint8_t zeros[256]; memset(zeros, 0, sizeof(zeros));
    double e_zero = msx_shannon_entropy(zeros, sizeof(zeros));
    CHECK(e_zero == 0.0, "all-zero buffer has zero entropy");

    uint8_t uniform[256];
    for (int i = 0; i < 256; i++) uniform[i] = (uint8_t)i;
    double e_uniform = msx_shannon_entropy(uniform, sizeof(uniform));
    CHECK(fabs(e_uniform - 8.0) < 0.001, "uniform byte distribution has ~8.0 bits entropy");

    CHECK(msx_shannon_entropy(NULL, 0) == 0.0, "empty buffer returns zero entropy safely");
}

static void test_sha256(void) {
    printf("test_sha256:\n");
    char hex[65];
    /* SHA-256("") and SHA-256("abc") are well-known FIPS 180-4 test vectors. */
    msx_sha256_hex((const uint8_t *)"", 0, hex);
    CHECK(strlen(hex) == 64, "sha256('') hex is 64 characters");
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "sha256('') matches known test vector");

    msx_sha256_hex((const uint8_t *)"abc", 3, hex);
    CHECK(strlen(hex) == 64, "sha256('abc') hex is 64 characters");
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256('abc') matches known test vector");
}

static void test_scoring(void) {
    printf("test_scoring:\n");
    msx_score_report_t rep;
    msx_score_report_init(&rep);
    CHECK(rep.total == 0 && rep.risk == MSX_RISK_NONE, "fresh report starts at zero/none");

    msx_score_add(&rep, 20, "test finding A");
    msx_score_add(&rep, 30, "test finding B");
    CHECK(rep.total == 50, "score accumulates correctly");
    CHECK(rep.risk == MSX_RISK_MEDIUM, "50 points maps to Medium risk");
    CHECK(rep.entries.count == 2, "two explanation entries recorded");

    msx_score_report_free(&rep);
}

int main(void) {
    test_entropy();
    test_sha256();
    test_scoring();

    printf("\n%s (%d failures)\n", g_failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_failures);
    return g_failures == 0 ? 0 : 1;
}
