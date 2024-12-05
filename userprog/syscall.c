#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/syscall.h"

#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);
static int32_t get_user (const uint8_t *uaddr);
static int memread_from_user (void *src, void *des, size_t bytes);

struct lock filesys_lock;

static struct file_desc* find_file_desc_(struct thread *, int fd);

/** System Call Handler Function Declarations **/
void sys_halt(void);
void sys_exit(int status);
tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t child_tid);
bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char *file);
int sys_read(int fd, void *buffer, unsigned size);
int sys_filesize(int fd);
int sys_write(int fd, const void*buffer, unsigned size);
void sys_seek(int fd, unsigned pos);
unsigned sys_tell(int fd);
void sys_close(int fd);

void
syscall_init(void)
{
    lock_init (&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int32_t
check_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
    // check that a user pointer `udst` points below PHYS_BASE
    if (! ((void*)udst < PHYS_BASE)) {
        return false;
    }

    int error_code;

    // as suggested in the reference manual, see (3.1.5)
    asm ("movl $1f, %0; movb %b2, %1; 1:"
            : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

//verify pointer is valid and mapped
bool is_valid_user_address(const void *buffer, unsigned size) {
	for (unsigned i = 0; i < size; i++) {
		const void *addr = (const char *)buffer + i;
		if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
			return false;
		}
	}
	return true;
}

static int
memread_from_user(void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = check_user(src + i);

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

static struct file_desc*
find_file_desc_(struct thread *t, int fd)
{
    if (fd < 3) {  // Skip stdin, stdout, stderr
        return NULL;
    }

    for (struct list_elem *e = list_begin(&t->file_descriptors);
         e != list_end(&t->file_descriptors);
         e = list_next(e))
    {
        struct file_desc *desc = list_entry(e, struct file_desc, elem);
        if (desc->id == fd) {
            return desc;
        }
    }

    return NULL;  // Not found
}

//int sys_wait(tid_t tid) {
//	return process_wait(tid);
//}

static void
syscall_handler(struct intr_frame *f)
{
    // Validate the stack pointer (esp)
    if (f->esp == NULL || !is_user_vaddr(f->esp) || pagedir_get_page(thread_current()->pagedir, f->esp) == NULL) {
        sys_exit(-1);
    }

	uint32_t *esp = f->esp;

	switch (*esp)
	{

	case SYS_HALT: // 0
	{
		sys_halt();
		NOT_REACHED();
		break;
	}

    case SYS_EXEC: // 2
    {
        void* cmdline;
        memread_from_user(f->esp + 4, &cmdline, sizeof(cmdline));

        int return_code = sys_exec((const char*) cmdline);
        f->eax = (uint32_t) return_code;
        break;
    }

    case SYS_WAIT: // 3
    {
        pid_t pid;
        memread_from_user(f->esp + 4, &pid, sizeof(pid_t));

        int ret = sys_wait(pid);
        f->eax = (uint32_t) ret;
        break;
    }

	case SYS_EXIT:
	{
		int exitcode;
      	memread_from_user(f->esp + 4, &exitcode, sizeof(exitcode));

      	sys_exit(exitcode);
      	NOT_REACHED();
      	break;
	}

    case SYS_READ:
	{

		int fd, return_code;
      	void *buffer;
      	unsigned size;

      	memread_from_user(f->esp + 4, &fd, sizeof(fd));
      	memread_from_user(f->esp + 8, &buffer, sizeof(buffer));
      	memread_from_user(f->esp + 12, &size, sizeof(size));

      	return_code = sys_read(fd, buffer, size);
      	f->eax = (uint32_t) return_code;
      	break;
	}

	case SYS_OPEN:
    {
      const char* filename;
      int return_code;

      memread_from_user(f->esp + 4, &filename, sizeof(filename));

      return_code = sys_open(filename);
      f->eax = return_code;
      break;
    }

    case SYS_FILESIZE:
    {
        int fd, ret;
        memread_from_user(f->esp + 4, &fd, sizeof(fd));

        ret = sys_filesize(fd);
        f->eax = ret;
        break;
    }

	case SYS_WRITE:
	{
        int fd;
        const void *buffer;
        unsigned size;

        /* Validate and extract arguments from user stack */
        memread_from_user(f->esp + 4, &fd, sizeof(fd));
        memread_from_user(f->esp + 8, &buffer, sizeof(buffer));
        memread_from_user(f->esp + 12, &size, sizeof(size));

        /* Pass the arguments to the sys_write implementation */
        f->eax = sys_write(fd, buffer, size);
        break;
	}

	case SYS_CREATE:
	{
	  const char* filename;
      unsigned initial_size;
      bool return_code;

      memread_from_user(f->esp + 4, &filename, sizeof(filename));
      memread_from_user(f->esp + 8, &initial_size, sizeof(initial_size));

      return_code = sys_create(filename, initial_size);
      f->eax = return_code;
      break;
	}

	case SYS_REMOVE:
	{
		const char* filename;
		bool return_code;

		memread_from_user(f->esp + 4, &filename, sizeof(filename));

		return_code = sys_remove(filename);
		f->eax = return_code;
		break;
	}

    case SYS_SEEK:
    {
        int fd;
        unsigned position;

        memread_from_user(f->esp + 4, &fd, sizeof(fd));
        memread_from_user(f->esp + 8, &position, sizeof(position));

        sys_seek(fd, position);
        break;
    }

    case SYS_TELL:
    {
        int fd;
        unsigned return_code;

        memread_from_user(f->esp + 4, &fd, sizeof(fd));

        return_code = sys_tell(fd);
        f->eax = (uint32_t) return_code;
        break;
    }

     case SYS_CLOSE: // 12
     {
         int fd;
         memread_from_user(f->esp + 4, &fd, sizeof(fd));

         sys_close(fd);
         break;
     }
	default:
		sys_exit(-1);
	}
}


/** System Call Handler Function Implementations **/

void sys_halt(void) {
    shutdown_power_off();
}

static int sys_wait(tid_t child_tid) {
    return process_wait(child_tid);
}

void sys_exit(int status) {
    printf("%s: exit(%d)\n", thread_current()->name, status);

    struct process_control_block *pcb = thread_current()->pcb;
    if(pcb != NULL) {
        pcb->exitcode = status;
    }

    thread_exit();
}

int sys_write(int fd, const void*buffer, unsigned size)
{
    int ret = -1;

    // Validate buffer pointer and memory range
    if (buffer == NULL) {
        sys_exit(-1);  // Null buffer is invalid
    }

    for (size_t i = 0; i < size; i++) {
        if (!is_user_vaddr((char *)buffer + i) || pagedir_get_page(thread_current()->pagedir, (char *)buffer + i) == NULL) {
            sys_exit(-1);  // Invalid user memory
        }
    }

    lock_acquire(&filesys_lock);

    // Handle stdout separately without locking
    if (fd == 1) {  // stdout
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    // Validate file descriptor and perform file write
    if (fd < 2) {  // Invalid file descriptors: 0 (stdin) and negative values
        lock_release(&filesys_lock);
        return -1;
    }

    struct file_desc *file_d = find_file_desc_(thread_current(), fd);
    if (file_d && file_d->file) {
        ret = file_write(file_d->file, buffer, size);
    } else {
        ret = -1;  // Invalid FD or file not open
    }

    lock_release(&filesys_lock);
    return ret;
}

int sys_filesize(int fd) {
    struct file_desc* file_d;

    lock_acquire (&filesys_lock);
    file_d = find_file_desc_(thread_current(), fd);

    if(file_d == NULL) {
        lock_release (&filesys_lock);
        return -1;
    }

    int ret = file_length(file_d->file);
    lock_release (&filesys_lock);
    return ret;
}

bool sys_create(const char* filename, unsigned initial_size) {

    if (filename == NULL || !is_user_vaddr(filename)) {
        sys_exit(-1);  // Invalid file name
    }

    // Ensure filename is a valid, null-terminated string
    if (pagedir_get_page(thread_current()->pagedir, filename) == NULL) {
        sys_exit(-1);  // Invalid memory
    }

    // Validate length
    if (strlen(filename) == 0) {
        sys_exit(-1);  // Invalid size
    }

    bool return_code;
    return_code = filesys_create(filename, initial_size, false);
    return return_code;
}

bool sys_remove(const char* filename) {
    bool return_code;

    if (filename == NULL || !is_user_vaddr(filename)) {
        sys_exit(-1);
    }

    if (pagedir_get_page(thread_current()->pagedir, filename) == NULL) {
        sys_exit(-1);
    }

    lock_acquire(&filesys_lock);
    struct file *file = filesys_open(filename);
    if (file != NULL) {
        file_close(file);  // Close our temporary reference
    }

    return_code = filesys_remove(filename);
    lock_release(&filesys_lock);

    return return_code;
}

int sys_open(const char *file_name) {

    if (file_name == NULL || !is_user_vaddr(file_name)) {
        sys_exit(-1);  // Invalid file name
    }

    // Ensure filename is a valid, null-terminated string
    if (pagedir_get_page(thread_current()->pagedir, file_name) == NULL) {
        sys_exit(-1);  // Invalid memory
    }

    lock_acquire(&filesys_lock);

    // Attempt to open the file
    struct file *file_opened = filesys_open(file_name);
    if (file_opened == NULL) {
        lock_release(&filesys_lock);
        return -1;   // File could not be opened
    }

    // Allocate memory for a file descriptor structure
    struct file_desc *fd_entry = malloc(sizeof(struct file_desc));
    if (fd_entry == NULL) {
        file_close(file_opened);  // Clean up the opened file
        lock_release(&filesys_lock);
        sys_exit(-1);   // Memory allocation failed
    }

    // Initialize the file descriptor structure
    fd_entry->file = file_opened;
    fd_entry->id = ++thread_current()->max_fd;  // Assign the next available FD

    // Add the file descriptor to the current thread's list
    list_push_back(&thread_current()->file_descriptors, &fd_entry->elem);

    lock_release(&filesys_lock);
    return fd_entry->id;

}

int sys_read(int fd, void *buffer, unsigned size) {
    int ret;

    if (buffer == NULL || !is_user_vaddr(buffer)) {
        sys_exit(-1);
    }

    // Check if buffer range is valid (start and end addresses)
    if (!is_user_vaddr(buffer + size - 1)) {
        sys_exit(-1);
    }

    // Check if buffer is mapped in page directory
    if (pagedir_get_page(thread_current()->pagedir, buffer) == NULL) {
        sys_exit(-1);
    }

    if (size == 0) {
        return 0;  // Nothing to read
    }

    lock_acquire(&filesys_lock);

    // stdin
    if (fd == 0) {
        unsigned i;
        char *char_buffer = (char *)buffer;
        for (i = 0; i < size; ++i) {
            char_buffer[i] = input_getc();
        }
        ret = size;
    }
    else{
        struct file_desc* file_d = find_file_desc_(thread_current(), fd);

        if(file_d && file_d->file) {
            ret = file_read(file_d->file, buffer, size);
        }
        else{
            ret = -1;
        }
    }

    lock_release(&filesys_lock);
    return ret;
}

void sys_seek(int fd, unsigned position) {
    lock_acquire (&filesys_lock);
    struct file_desc* file_d = find_file_desc_(thread_current(), fd);

    if(file_d && file_d->file) {
        file_seek(file_d->file, position);
    }
    else {
    }

    lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
    lock_acquire (&filesys_lock);
    struct file_desc* file_d = find_file_desc_(thread_current(), fd);

    unsigned ret;
    if(file_d && file_d->file) {
        ret = file_tell(file_d->file);
    }
    else {
    }

    lock_release (&filesys_lock);
    return ret;
}

void sys_close(int fd) {

    lock_acquire(&filesys_lock);
    struct file_desc *file_d = find_file_desc_(thread_current(), fd);

    //check valid and non-null fd
    if (file_d && file_d->file) {
        file_close(file_d->file);

        // close dir if it is directory
        if (file_d->dir) {
            list_remove(&(file_d->elem));
        }
        list_remove(&(file_d->elem));
        free(file_d);
    }
    lock_release(&filesys_lock);
}


tid_t sys_exec(const char *cmd_line) {
    if (cmd_line == NULL || !is_user_vaddr(cmd_line)) {
        sys_exit(-1);  // Invalid file name
    }

    // Ensure filename is a valid, null-terminated string
    if (pagedir_get_page(thread_current()->pagedir, cmd_line) == NULL) {
        sys_exit(-1);  // Invalid memory
    }

    return process_execute(cmd_line);
}

