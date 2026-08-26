#ifndef GHOST_TASK_SAFETY_CHECKS_H
#define GHOST_TASK_SAFETY_CHECKS_H

static int GhostTaskInitSliverParser(datap *parser, char *buffer, unsigned int length)
{
    unsigned char *prefix = (unsigned char *)buffer;
    unsigned int declaredLength = 0;

    if (parser == NULL || buffer == NULL || length < 4 || length > 0x7fffffffU)
        return 0;
    declaredLength = (unsigned int)prefix[0] |
                     ((unsigned int)prefix[1] << 8) |
                     ((unsigned int)prefix[2] << 16) |
                     ((unsigned int)prefix[3] << 24);
    if (declaredLength != length - 4)
        return 0;

    parser->original = buffer;
    parser->buffer = buffer + 4;
    parser->length = (int)declaredLength;
    parser->size = (int)declaredLength;
    return 1;
}

/*
 * COFFLoader's BeaconDataExtract compatibility function trusts the declared
 * blob length. Parse Sliver's fixed string fields directly so a malformed
 * prefix can never advance beyond the actual argument buffer.
 */
static int GhostTaskExtractSliverField(datap *parser, unsigned int maxContentLength, char **value)
{
    unsigned char *prefix = NULL;
    unsigned int declaredLength = 0;
    unsigned int index = 0;

    if (parser == NULL || value == NULL || parser->buffer == NULL || parser->length < 4)
        return 0;

    prefix = (unsigned char *)parser->buffer;
    declaredLength = (unsigned int)prefix[0] |
                     ((unsigned int)prefix[1] << 8) |
                     ((unsigned int)prefix[2] << 16) |
                     ((unsigned int)prefix[3] << 24);
    if (declaredLength < 1 ||
        declaredLength > maxContentLength + 1 ||
        declaredLength > (unsigned int)(parser->length - 4))
        return 0;

    *value = parser->buffer + 4;
    if ((*value)[declaredLength - 1] != '\0')
        return 0;
    for (index = 0; index < declaredLength - 1; index++)
    {
        if ((*value)[index] == '\0')
            return 0;
    }

    parser->buffer += 4 + declaredLength;
    parser->length -= 4 + declaredLength;
    return 1;
}

static int GhostTaskHasSupportedSidSize(unsigned int sizeOfSid)
{
    return sizeOfSid == 12 || sizeOfSid == 28;
}

static int GhostTaskHasSafeTaskName(const char *taskName)
{
    unsigned int length = 0;
    int previousWasSeparator = 0;

    if (taskName == NULL || taskName[0] == '\0')
        return 0;
    while (taskName[length] != '\0')
    {
        if (length == 190)
            return 0;
        if (taskName[length] == '\\')
        {
            if (length == 0 || previousWasSeparator)
                return 0;
            previousWasSeparator = 1;
        }
        else
        {
            previousWasSeparator = 0;
        }
        length++;
    }
    return !previousWasSeparator;
}

static int GhostTaskIsHexDigit(char value)
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

static int GhostTaskIsValidGuid(const char *value, unsigned int byteLength)
{
    unsigned int index = 0;

    if (value == NULL || byteLength != 39 || value[0] != '{' ||
        value[37] != '}' || value[38] != '\0')
        return 0;
    for (index = 1; index < 37; index++)
    {
        if (index == 9 || index == 14 || index == 19 || index == 24)
        {
            if (value[index] != '-')
                return 0;
        }
        else if (!GhostTaskIsHexDigit(value[index]))
        {
            return 0;
        }
    }
    return 1;
}

static int GhostTaskSliverBufferConsumed(datap *parser)
{
    return parser != NULL && parser->length == 0;
}

#endif
