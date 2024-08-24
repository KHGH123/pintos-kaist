#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/synch.h"


void syscall_entry (void);
void syscall (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

bool badptr (void *ptr) {
	if (!ptr || is_kernel_vaddr (ptr) || !pml4_get_page (thread_current ()->pml4, ptr))
		exit (-1);
}
void halt (void) {
	power_off ();
}

void exit (int status) {
	thread_current ()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current ()->name, status);
	thread_exit ();
}

tid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork (thread_name, f);	
}

int exec (const char *cmd_line) {	
	badptr (cmd_line);
	if (process_exec (cmd_line) == -1) exit(-1);
}

int wait (tid_t pid) {
	return process_wait (pid);
}

bool create (const char *file, unsigned int initial_size) {
	badptr (file);
	if (!file) exit (-1);
	return filesys_create (file, initial_size);
}

bool remove (const char *file) {
	badptr (file);
	return filesys_remove (file);
}

int open (const char *file) {
	badptr (file);
	int idx = 0;
	while (thread_current ()->fd_table[idx] && idx < 64)
		idx++;

	thread_current ()->fd_table[idx] = filesys_open (file);
	if (!thread_current ()->fd_table[idx]) 
		return -1;
	else
		return idx + 2;	
}

int filesize (int fd) {
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return 0;
	return file_length (thread_current ()->fd_table[fd - 2]);
}

int read (int fd, void *buffer, unsigned size) {
	badptr (buffer);
	if (fd < 0 || fd > 63 ||fd == STDOUT_FILENO || !thread_current ()->fd_table[fd - 2])
		return -1;
	else if (fd == STDIN_FILENO) {
		char *p = (char *)buffer;
		char c;
		while (c = input_getc () != '\n') {
			*p = c;
			p++;
		}
		*p = '\0';
		return (char *)buffer - p;
	}
	else
		return file_read (thread_current ()->fd_table[fd - 2], buffer, size);
}

int write (int fd, const void *buffer, unsigned size) {
	badptr (buffer);
	if (fd < 0 || fd > 63 || fd == STDIN_FILENO || !thread_current ()->fd_table[fd - 2])
		return -1;
	else if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	else 
		return file_write (thread_current ()->fd_table[fd - 2], buffer, size);
}

void seek (int fd, unsigned position) {
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return;
	file_seek (thread_current ()->fd_table[fd - 2], position);
}

unsigned tell (int fd) {
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return;
	return file_tell (thread_current ()->fd_table[fd - 2]);
}

void close (int fd) {
	if (fd < 0 || fd > 63 || fd == STDIN_FILENO || fd == STDOUT_FILENO) exit (-1);
	thread_current ()->fd_table [fd - 2] = NULL;
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt ();
		break;
	
	case SYS_EXIT:
		exit (f->R.rdi);
		f->R.rax = f->R.rdi;
		break;
	
	case SYS_FORK:
		f->R.rax = fork (f->R.rdi, f);
		break;
	
	case SYS_EXEC:
		f->R.rax = exec (f->R.rdi);
		break;
	
	case SYS_WAIT:
		f->R.rax = wait (f->R.rdi);
		break;

	case SYS_CREATE: 
		f->R.rax = create (f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE: 
		f->R.rax = remove (f->R.rdi);
		break;
	
	case SYS_OPEN:
		f->R.rax = open (f->R.rdi);
		break;

	case SYS_FILESIZE:
		f->R.rax = filesize (f->R.rdi);
		break;
	
	case SYS_READ:
		f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	
	case SYS_WRITE:
		f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	
	case SYS_SEEK:
		seek (f->R.rdi, f->R.rsi);
		break;
	
	case SYS_TELL:
		tell (f->R.rdi);
		break;
	
	case SYS_CLOSE:
		close (f->R.rdi);
		break;
	
	default:
		exit (-1);
		break;
	}
	return;	
}
