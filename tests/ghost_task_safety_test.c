#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

#include "../src/Remote/ghost_task/safety_checks.h"

static size_t AppendField(unsigned char *buffer, size_t offset, const char *value, size_t contentLength)
{
    unsigned int declaredLength = (unsigned int)contentLength + 1;

    buffer[offset++] = (unsigned char)(declaredLength & 0xff);
    buffer[offset++] = (unsigned char)((declaredLength >> 8) & 0xff);
    buffer[offset++] = (unsigned char)((declaredLength >> 16) & 0xff);
    buffer[offset++] = (unsigned char)((declaredLength >> 24) & 0xff);
    memcpy(buffer + offset, value, contentLength);
    buffer[offset + contentLength] = '\0';
    return offset + declaredLength;
}

static void TestAllNineFieldsAndTruncations(void)
{
    static const char *values[9] = {
        "localhost", "delete", "demo", "", "", "", "", "", "",
    };
    static const unsigned int maxLengths[9] = {255, 255, 190, 255, 255, 255, 255, 255, 255};
    unsigned char buffer[512] = {0};
    size_t fieldEnds[9] = {0};
    size_t length = 0;
    int field = 0;

    for (field = 0; field < 9; field++)
    {
        length = AppendField(buffer, length, values[field], strlen(values[field]));
        fieldEnds[field] = length;
    }

    datap valid = {(char *)buffer, (char *)buffer, (int)length, (int)length};
    for (field = 0; field < 9; field++)
    {
        char *value = NULL;
        assert(GhostTaskExtractSliverField(&valid, maxLengths[field], &value));
        assert(strcmp(value, values[field]) == 0);
    }
    assert(GhostTaskSliverBufferConsumed(&valid));

    datap trailing = {(char *)buffer, (char *)buffer, (int)length + 1, (int)length + 1};
    for (field = 0; field < 9; field++)
    {
        char *value = NULL;
        assert(GhostTaskExtractSliverField(&trailing, maxLengths[field], &value));
    }
    assert(!GhostTaskSliverBufferConsumed(&trailing));

    for (field = 0; field < 9; field++)
    {
        datap truncated = {(char *)buffer, (char *)buffer, (int)fieldEnds[field] - 1, (int)fieldEnds[field] - 1};
        int preceding = 0;
        for (preceding = 0; preceding < field; preceding++)
        {
            char *value = NULL;
            assert(GhostTaskExtractSliverField(&truncated, maxLengths[preceding], &value));
        }
        char *value = NULL;
        assert(!GhostTaskExtractSliverField(&truncated, maxLengths[field], &value));
    }
}

static void TestEnvelopeValidation(void)
{
    char valid[] = {0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    char shortDeclared[] = {0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    char longDeclared[] = {0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    datap parser = {0};

    assert(GhostTaskInitSliverParser(&parser, valid, sizeof(valid)));
    assert(parser.original == valid);
    assert(parser.buffer == valid + 4);
    assert(parser.length == 4 && parser.size == 4);
    assert(!GhostTaskInitSliverParser(&parser, NULL, sizeof(valid)));
    assert(!GhostTaskInitSliverParser(&parser, valid, 3));
    assert(!GhostTaskInitSliverParser(&parser, valid, sizeof(valid) - 1));
    assert(!GhostTaskInitSliverParser(&parser, shortDeclared, sizeof(shortDeclared)));
    assert(!GhostTaskInitSliverParser(&parser, longDeclared, sizeof(longDeclared)));
}

static void TestTaskNameBoundary(void)
{
    unsigned char buffer[1024] = {0};
    char task190[191] = {0};
    char task191[192] = {0};
    size_t length = 0;
    char *value = NULL;
    int index = 0;

    memset(task190, 'A', 190);
    memset(task191, 'B', 191);

    assert(!GhostTaskHasSafeTaskName(NULL));
    assert(!GhostTaskHasSafeTaskName(""));
    assert(GhostTaskHasSafeTaskName(task190));
    assert(!GhostTaskHasSafeTaskName(task191));
    assert(!GhostTaskHasSafeTaskName("\\"));
    assert(!GhostTaskHasSafeTaskName("foo\\"));
    assert(!GhostTaskHasSafeTaskName("foo\\\\bar"));
    assert(GhostTaskHasSafeTaskName("foo\\bar"));

    length = AppendField(buffer, length, "localhost", 9);
    length = AppendField(buffer, length, "delete", 6);
    length = AppendField(buffer, length, task190, 190);
    datap accepted = {(char *)buffer, (char *)buffer, (int)length, (int)length};
    for (index = 0; index < 2; index++)
        assert(GhostTaskExtractSliverField(&accepted, 255, &value));
    assert(GhostTaskExtractSliverField(&accepted, 190, &value));
    assert(strlen(value) == 190);

    memset(buffer, 0, sizeof(buffer));
    length = AppendField(buffer, 0, "localhost", 9);
    length = AppendField(buffer, length, "delete", 6);
    length = AppendField(buffer, length, task191, 191);
    datap rejected = {(char *)buffer, (char *)buffer, (int)length, (int)length};
    for (index = 0; index < 2; index++)
        assert(GhostTaskExtractSliverField(&rejected, 255, &value));
    assert(!GhostTaskExtractSliverField(&rejected, 190, &value));
}

static void TestGenericStringBoundary(void)
{
    unsigned char buffer[512] = {0};
    char value255[256] = {0};
    char value256[257] = {0};
    char *value = NULL;
    size_t length = 0;

    memset(value255, 'C', 255);
    memset(value256, 'D', 256);

    length = AppendField(buffer, 0, value255, 255);
    datap accepted = {(char *)buffer, (char *)buffer, (int)length, (int)length};
    assert(GhostTaskExtractSliverField(&accepted, 255, &value));
    assert(strlen(value) == 255);

    memset(buffer, 0, sizeof(buffer));
    length = AppendField(buffer, 0, value256, 256);
    datap rejected = {(char *)buffer, (char *)buffer, (int)length, (int)length};
    assert(!GhostTaskExtractSliverField(&rejected, 255, &value));
}

static void TestMalformedFieldsAndSidSizes(void)
{
    unsigned char oversized[] = {0xff, 0xff, 0xff, 0xff};
    unsigned char embeddedNul[] = {0x03, 0x00, 0x00, 0x00, 'A', '\0', '\0'};
    char *value = NULL;
    datap parser = {(char *)oversized, (char *)oversized, (int)sizeof(oversized), (int)sizeof(oversized)};

    assert(!GhostTaskExtractSliverField(&parser, 255, &value));
    parser.original = (char *)embeddedNul;
    parser.buffer = (char *)embeddedNul;
    parser.length = (int)sizeof(embeddedNul);
    parser.size = (int)sizeof(embeddedNul);
    assert(!GhostTaskExtractSliverField(&parser, 255, &value));

    assert(GhostTaskHasSupportedSidSize(12));
    assert(GhostTaskHasSupportedSidSize(28));
    assert(!GhostTaskHasSupportedSidSize(0));
    assert(!GhostTaskHasSupportedSidSize(11));
    assert(!GhostTaskHasSupportedSidSize(13));
    assert(!GhostTaskHasSupportedSidSize(27));
    assert(!GhostTaskHasSupportedSidSize(29));
    assert(!GhostTaskHasSupportedSidSize(68));
}

static void TestGuidValidation(void)
{
    char valid[] = "{01234567-89ab-CDEF-0123-456789abcdef}";
    char wrongShape[] = "{0123456789ab-CDEF-0123-456789abcdef}";
    char nonHex[] = "{0123456Z-89ab-CDEF-0123-456789abcdef}";
    char noTerminator[39] = "{01234567-89ab-CDEF-0123-456789abcdef}";

    noTerminator[38] = 'X';
    assert(GhostTaskIsValidGuid(valid, sizeof(valid)));
    assert(!GhostTaskIsValidGuid(valid, sizeof(valid) - 1));
    assert(!GhostTaskIsValidGuid(wrongShape, sizeof(wrongShape)));
    assert(!GhostTaskIsValidGuid(nonHex, sizeof(nonHex)));
    assert(!GhostTaskIsValidGuid(noTerminator, sizeof(noTerminator)));
}

int main(void)
{
    TestAllNineFieldsAndTruncations();
    TestEnvelopeValidation();
    TestTaskNameBoundary();
    TestGenericStringBoundary();
    TestMalformedFieldsAndSidSizes();
    TestGuidValidation();
    puts("ghost_task safety tests passed");
    return 0;
}
