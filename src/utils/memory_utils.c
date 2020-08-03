#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "memory_utils.h"

#define DAWN_MEM_FILENAME_LEN 20
struct mem_list {
	struct mem_list* next_mem;
	int line;
	char file[DAWN_MEM_FILENAME_LEN];
	char type;
	size_t size;
	void* ptr;
};

struct mem_list* mem_base = NULL;

void* dawn_memory_alloc(enum dawn_memop type, char* file, int line, size_t nmemb, size_t size, void *ptr)
{
	void* ret = NULL;

	switch (type)
	{
	case DAWN_MALLOC:
		ret = malloc(size);
		break;
	case DAWN_REALLOC:
		dawn_memory_unregister(DAWN_REALLOC, file, line, ptr);
		ret = realloc(ptr, size);
		break;
	case DAWN_CALLOC:
		ret = calloc(nmemb, size);
		size *= nmemb; // May not be correct allowing for padding but gives a sense of scale
		break;
	default:
		break;
	}

	if (ret != NULL)
		dawn_memory_register(type, file, line, size, ret);

	return ret;
}

void* dawn_memory_register(enum dawn_memop type, char* file, int line, size_t size, void* ptr)
{
	void* ret = NULL;
	struct mem_list* this_log = NULL;
	char type_c = '?';

	// Ignore over enthusiastic effort to  register a failed allocation
	if (ptr == NULL)
		return ret;

	switch (type)
	{
	case DAWN_MALLOC:
		type_c = 'M';
		break;
	case DAWN_REALLOC:
		type_c = 'R';
		break;
	case DAWN_CALLOC:
		type_c = 'C';
		break;
	case DAWN_MEMREG:
		type_c = 'X';
		break;
	default:
		printf("Unexpected memory op tag!\n");
		break;
	}

	// Insert to linked list with ascending memory reference
	struct mem_list** ipos = &mem_base;
	while (*ipos != NULL && (*ipos)->ptr < ptr)
		ipos = &((*ipos)->next_mem);

	if (*ipos != NULL && (*ipos)->ptr == ptr)
	{
		printf("attempting to register memory already registered (%c@%s:%d)...\n", type_c, file, line);
	}
	else
	{
		this_log = malloc(sizeof(struct mem_list));

		if (this_log == NULL)
		{
			printf("Oh the irony! malloc() failed in dawn_memory_register()!\n");
		}
		else
		{
			this_log->next_mem = *ipos;
			*ipos = this_log;

			// Just use filename - no path
			file = strrchr(file, '/');

			if (file != NULL)
				strncpy(this_log->file, file + 1, DAWN_MEM_FILENAME_LEN);
			else
				strncpy(this_log->file, "?? UNKNOWN ??", DAWN_MEM_FILENAME_LEN);

			this_log->type = type_c;
			this_log->line = line;
			this_log->ptr = ptr;
			this_log->size = size;
		}
	}

	return ret;
}

void dawn_memory_unregister(enum dawn_memop type, char* file, int line, void* ptr)
{
	struct mem_list** mem = &mem_base;
	char type_c = '?';

	while (*mem != NULL && (*mem)->ptr <= ptr)
	{
		mem = &((*mem)->next_mem);
	}

	switch (type)
	{
	case DAWN_FREE:
		type_c = 'F';
		break;
	case DAWN_MEMUNREG:
		type_c = 'U';
		break;
	case DAWN_REALLOC:
		type_c = 'R';
		break;
	default:
		printf("Unexpected memory op tag!\n");
		break;
	}

	if (*mem != NULL && (*mem)->ptr == ptr)
	{
		struct mem_list* tmp = *mem;
		*mem = tmp->next_mem;
		free(tmp);
	}
	else
	{
		printf("Releasing (%c) memory we hadn't registered (%s:%d)...\n", type_c, file, line);
	}

	return;
}

void dawn_memory_free(enum dawn_memop type, char* file, int line, void* ptr)
{
	dawn_memory_unregister(type, file, line, ptr);
	
	free(ptr);

	return;
}

void dawn_memory_audit()
{
	printf("Currently recorded memory allocations...\n");
	for (struct mem_list* mem = mem_base; mem != NULL; mem = mem->next_mem)
	{
		printf("%c - %s@%d: %ld\n", mem->type, mem->file, mem->line, mem->size);
	}
	printf("[End of memory allocation list]\n");
}
