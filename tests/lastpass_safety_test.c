#include <assert.h>
#include <stdio.h>

#include "../src/Remote/lastpass/safety_checks.h"

int main(void)
{
    char valid[] = {0x04, 0x00, 0x00, 0x00, (char)0xd2, 0x04, 0x00, 0x00};
    char zero[] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char negative[] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (char)0x80};
    char wrongOuterShort[] = {0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    char wrongOuterLong[] = {0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    char trailing[] = {0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    char recordFixture[] = "0123456789ApayloadDELIMITERguard";
    int pid = 0;
    const char *payload = NULL;
    unsigned int payloadLength = 0;
    unsigned int recordLength = 0;

    assert(LastPassParseSliverPid(valid, sizeof(valid), &pid));
    assert(pid == 1234);
    assert(!LastPassParseSliverPid(NULL, sizeof(valid), &pid));
    assert(!LastPassParseSliverPid(valid, sizeof(valid) - 1, &pid));
    assert(!LastPassParseSliverPid(wrongOuterShort, sizeof(wrongOuterShort), &pid));
    assert(!LastPassParseSliverPid(wrongOuterLong, sizeof(wrongOuterLong), &pid));
    assert(!LastPassParseSliverPid(trailing, sizeof(trailing), &pid));
    assert(!LastPassParseSliverPid(zero, sizeof(zero), &pid));
    assert(!LastPassParseSliverPid(negative, sizeof(negative), &pid));

    assert(LastPassPayloadBounds(
        recordFixture,
        (int)sizeof(recordFixture) - 1,
        recordFixture + 18,
        11,
        &payload,
        &payloadLength));
    assert(payload == recordFixture + 11);
    assert(payloadLength == 7);
    assert(payload[0] == 'p' && payload[6] == 'd');
    assert(LastPassRecordSize(0x18, payloadLength, &recordLength));
    assert(recordLength == 0x1f);
    assert(recordFixture[11 + payloadLength] == 'D');
    assert(!LastPassPayloadBounds(recordFixture, 17, recordFixture + 18, 11, &payload, &payloadLength));
    assert(!LastPassPayloadBounds(recordFixture, 19, recordFixture + 10, 11, &payload, &payloadLength));
    assert(!LastPassRecordSize(0x18, ~0U, &recordLength));

    /* JSON data includes its delimiter; generic/private-key records stop at it. */
    assert(LastPassPayloadBounds(recordFixture, 30, recordFixture + 21, 11, &payload, &payloadLength));
    assert(payloadLength == 10);
    assert(LastPassRecordSize(0x18, payloadLength, &recordLength));
    assert(recordLength == 0x22);

    puts("lastpass safety tests passed");
    return 0;
}
