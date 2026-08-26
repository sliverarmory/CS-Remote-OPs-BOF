#ifndef LASTPASS_SAFETY_CHECKS_H
#define LASTPASS_SAFETY_CHECKS_H

static unsigned int LastPassReadLe32(const char *buffer)
{
    const unsigned char *bytes = (const unsigned char *)buffer;
    return (unsigned int)bytes[0] |
           ((unsigned int)bytes[1] << 8) |
           ((unsigned int)bytes[2] << 16) |
           ((unsigned int)bytes[3] << 24);
}

/* Sliver packs one integer as: uint32 body length, then raw uint32 value. */
static int LastPassParseSliverPid(const char *buffer, unsigned int length, int *pid)
{
    unsigned int bodyLength = 0;
    unsigned int rawPid = 0;

    if (buffer == NULL || pid == NULL || length != 8)
        return 0;

    bodyLength = LastPassReadLe32(buffer);
    if (bodyLength != 4 || bodyLength != length - 4)
        return 0;

    rawPid = LastPassReadLe32(buffer + 4);
    if (rawPid == 0 || rawPid > 0x7fffffffU)
        return 0;

    *pid = (int)rawPid;
    return 1;
}

/* Data records retain the historical payload offset while stopping exactly at
 * the located delimiter. This prevents bytes beyond the match from being
 * disclosed or emitted as synthetic zero padding. */
static int LastPassPayloadBounds(
    const char *buffer,
    int availableLength,
    const char *end,
    int payloadOffset,
    const char **payload,
    unsigned int *payloadLength)
{
    if (buffer == NULL || end == NULL || payload == NULL || payloadLength == NULL ||
        availableLength < 0 || payloadOffset < 0 || payloadOffset > availableLength)
        return 0;
    if (end < buffer + payloadOffset || end > buffer + availableLength)
        return 0;

    *payload = buffer + payloadOffset;
    *payloadLength = (unsigned int)(end - (buffer + payloadOffset));
    return 1;
}

static int LastPassRecordSize(
    unsigned int headerLength,
    unsigned int payloadLength,
    unsigned int *recordLength)
{
    if (recordLength == NULL || payloadLength > (~0U - headerLength))
        return 0;
    *recordLength = headerLength + payloadLength;
    return 1;
}

#endif
