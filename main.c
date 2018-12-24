#include "memutils.h"

int init_mod( void );
void free_mod( void );

unsigned long* g_sys_call_table = NULL;

EXPORT_SYMBOL( g_sys_call_table );

int get_count_syscalls( void )
{
	int count_syscalls, level;

	count_syscalls = 0;

	while ( true )
	{
		if ( g_sys_call_table[ count_syscalls ] == 0 )
			break;

		if ( lookup_address( g_sys_call_table[ count_syscalls ], &level )
			 == NULL )
			break;

		count_syscalls++;
	}

	return count_syscalls;
}

void replace_sys_call_table( void )
{
	// size of pointer * 2 (each bytes contains 2 chars) + 1 for null terminated
	// string.
	char bytes_of_syscalltable[ sizeof( g_sys_call_table ) * 2 + 1 ];
	sprintf( bytes_of_syscalltable, "%lX", ( unsigned long ) g_sys_call_table );

	c_printk( "sys_call_table (old endian): 0x%s\n", bytes_of_syscalltable );

	swap_endian( bytes_of_syscalltable, sizeof( bytes_of_syscalltable ) - 1 );
	bytes_of_syscalltable[ sizeof( g_sys_call_table ) * 2 ] = '\0';

	c_printk( "sys_call_table (swapped endian): 0x%s\n", bytes_of_syscalltable );
}

void update_sys_call_table_addr( void )
{
	pteval_t old_pte;

	c_printk(
	"task map base: %lX\n",
	map_base_task( find_task_from_addr( ( unsigned long ) init_module ) ) );

	g_sys_call_table
	= ( unsigned long* ) kallsyms_lookup_name( "sys_call_table" );

	c_printk( "kernel module loaded. test: 0x%02X, kernel .text: 0x%lX\n",
			  hex_char_to_byte( 'F', '3' ),
			  ( unsigned long ) kallsyms_lookup_name( "_text" ) );

	if ( g_sys_call_table == NULL )
		goto out;

	c_printk( "found g_sys_call_table (address of address: 0x%lX) address at: "
			  "0x%lX (first index: 0x%lX) count: %i\n",
			  ( unsigned long ) &g_sys_call_table,
			  *( unsigned long* ) &g_sys_call_table,
			  g_sys_call_table[ 0 ],
			  get_count_syscalls() );

	old_pte = get_page_prot( ( unsigned long ) g_sys_call_table );

	if ( !old_pte )
		goto out;

	c_printk( "sys_call_table: got old prots\n" );

	if ( !page_add_prot( ( unsigned long ) g_sys_call_table, _PAGE_RW ) )
		goto out;

	c_printk( "sys_call_table: page prots has been changed\n" );

	replace_sys_call_table();

	if ( !set_page_prot( ( unsigned long ) g_sys_call_table, old_pte ) )
		goto out;

	c_printk( "sys_call_table: reset prots\n" );

out:
	return;
}

int init_mod( void )
{
	update_sys_call_table_addr();
	return 0;
}

void free_mod( void ) { c_printk( "kernel module unloaded.\n" ); }

module_init( init_mod );
module_exit( free_mod );

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Xutax-Kamay" );
MODULE_DESCRIPTION( "Custom module" );
