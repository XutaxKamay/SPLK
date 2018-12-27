#include "memutils.h"

int init_mod( void );
void free_mod( void );

unsigned long* g_sys_call_table = NULL;
unsigned long* new_sys_call_table = NULL;

EXPORT_SYMBOL( new_sys_call_table );

int get_count_syscalls( unsigned long* table )
{
	int count_syscalls, level;

	count_syscalls = 0;

	while ( true )
	{
		if ( table[ count_syscalls ] == 0 )
			break;

		if ( lookup_address( table[ count_syscalls ], &level ) == NULL )
			break;

		count_syscalls++;
	}

	return count_syscalls;
}

void replace_sys_call_table( void )
{
	unsigned long do_syscall_64;
	unsigned long edo_syscall_64;
	char* pattern_g_syscalltable;
	unsigned long to_change, ra_syscalltable;
	int count;
	struct buffer_struct buf;
	pteval_t oldpteval;
	pte_t* pte;
	int level;

	to_change = 0;
	count = 0;
	do_syscall_64 = kallsyms_lookup_name( "do_syscall_64" );
	edo_syscall_64 = do_syscall_64 + PAGE_SIZE;
	pattern_g_syscalltable = "48 8B 4B 38 48 8B 73 68";
	memset( &buf, 0, sizeof( buf ) );

	if ( scan_pattern( do_syscall_64,
					   edo_syscall_64,
					   pattern_g_syscalltable,
					   strlen( pattern_g_syscalltable ) - 1,
					   &buf ) == 1 )
	{
		to_change = ( *( unsigned long* ) buf.addr ) - 4;
		count = get_count_syscalls( g_sys_call_table );

		// Let's reserve some space in the kernel code. We can safely use the
		// init segment as it just used at kernel init. We should check also if
		// we don't exceed the maximum memory we can allocate because it might
		// overwrite some segments we don't want to.
		new_sys_call_table = ( void* ) kallsyms_lookup_name( "_sinittext" );

		c_printk( "asking to reverse space at: %lX\n",
				  ( unsigned long ) new_sys_call_table );

		pte = lookup_address( ( unsigned long ) new_sys_call_table, &level );

		if ( pte != NULL )
		{
			oldpteval = pte->pte;
			pte->pte |= _PAGE_RW;

			memcpy( new_sys_call_table,
					g_sys_call_table,
					count * sizeof( void* ) );

			pte->pte = oldpteval;

			c_printk(
			"found new_sys_call_table (address of address: 0x%lX) address at: "
			"0x%lX (first index: 0x%lX) count: %i\n",
			( unsigned long ) &new_sys_call_table,
			*( unsigned long* ) &new_sys_call_table,
			new_sys_call_table[ 0 ],
			get_count_syscalls( new_sys_call_table ) );

			pte = lookup_address( to_change, &level );

			if ( pte != NULL )
			{
				ra_syscalltable = ( unsigned long ) new_sys_call_table &
				0xFFFFFFFF;

				oldpteval = pte->pte;
				pte->pte |= _PAGE_RW;

				memcpy( ( void* ) to_change, &ra_syscalltable, 4 );

				pte->pte = oldpteval;
				c_printk( "changed instructions\n" );
			}
			else
			{
				c_printk( "failed to get page to change instruction\n" );
			}
		}
		else
		{
			c_printk( "failed to create new sys call table\n" );
		}

		// 48 8B 04 D5 00 04 00 03
		for ( count = 0; count < 8; count++ )
		{
			pr_cont( "%02X ", *( unsigned char* ) ( to_change + count ) );
		}

		pr_cont( "\n" );
	}
}

void update_sys_call_table_addr( void )
{
	g_sys_call_table = ( unsigned long* ) kallsyms_lookup_name(
	"sys_call_table" );

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
			  get_count_syscalls( g_sys_call_table ) );

	replace_sys_call_table();

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
