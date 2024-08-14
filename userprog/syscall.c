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

void check_address(void *addr) {
	struct thread *t = thread_current();
	/* --- Project 2: User memory access --- */
	// if (!is_user_vaddr(addr)||addr == NULL) 
	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서 
	// pml4_get_page를 추가해줘야!
	if (!is_user_vaddr(addr)||addr == NULL||
	pml4_get_page(t->pml4, addr)== NULL)
	{
		exit(-1);
	}
}

void halt (void) {
	power_off ();
}

void exit (int status) {
	thread_exit ();
}

tid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork (thread_name, f);	
}

int exec (const char *cmd_line) {	
	if (process_exec (cmd_line) == -1) exit(-1);
}

int wait (tid_t pid) {
	process_wait (pid);
}

bool create (const char *file, unsigned int initial_size) {
	return filesys_create (file, initial_size);
}

bool remove (const char *file) {
	return filesys_remove (file);
}

int open (const char *file) {
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
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return;
	return file_length (thread_current ()->fd_table[fd - 2]);
}

int read (int fd, void *buffer, unsigned size) {
	if (fd == STDIN_FILENO) {
		char *p = (char *)buffer;
		char c;
		while (c = input_getc () != '\n') {
			*p = c;
			p++;
		}
		*p = '\0';
		return (char *)buffer - p;
	}
	else if (fd == STDOUT_FILENO || !thread_current ()->fd_table[fd - 2])
		return -1;
	else
		return file_read (thread_current ()->fd_table[fd - 2], buffer, size);
}

int write (int fd, const void *buffer, unsigned size) {
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	else if (fd == STDIN_FILENO || !thread_current ()->fd_table[fd - 2])
		return -1;
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
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return;
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
		break;
	
	case SYS_FORK:
		f->R.rax = fork (f->R.rdi, f);
		break;
	
	case SYS_EXEC:
		
		break;
	
	case SYS_WAIT:
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
		read (f->R.rdi, f->R.rsi, f->R.rdx);
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
		break;
	}
	return;
	// printf ("system call!\n");
	thread_exit ();
}