#ifndef KERNEL_CUSTOM_MEMUTILS
#define KERNEL_CUSTOM_MEMUTILS

#include "main.h"
#include "utils.h"

struct buffer_struct
{
	void* addr;
	size_t size;
};

void vm_flags_to_string( struct vm_area_struct* vma, char* output, int size );
int vm_flags_to_prot( struct vm_area_struct* vma );
int c_find_vma_from_task( struct task_struct* task,
						  struct vm_area_struct** vma_start,
						  unsigned long wanted_addr );
void c_print_vmas( struct task_struct* task );
int page_add_prot( unsigned long address, pteval_t prot );
int page_rm_prot( unsigned long address, pteval_t prot );
int set_page_prot( unsigned long address, pteval_t pteval );
pteval_t get_page_prot( unsigned long address );
struct task_struct* find_task_from_addr( unsigned long address );
int scan_task( struct task_struct* task,
			   char* pattern,
			   int len,
			   struct buffer_struct* buf );
int scan_kernel( char* start,
				 char* end,
				 char* pattern,
				 int len,
				 struct buffer_struct* buf );
unsigned long map_base_task( struct task_struct* task );
unsigned long kernel_offset( void );

#endif
