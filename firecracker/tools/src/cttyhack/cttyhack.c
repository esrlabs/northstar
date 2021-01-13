/* vi: set sw=4 ts=4: */
/*
 * Copyright (c) 2007 Denys Vlasenko <vda.linux@googlemail.com>
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>


#if !defined(__linux__) && !defined(TIOCGSERIAL) && !ENABLE_WERROR
# warning cttyhack will not be able to detect a controlling tty on this system
#endif

/* From <linux/vt.h> */
struct vt_stat {
	unsigned short v_active;        /* active vt */
	unsigned short v_signal;        /* signal to send */
	unsigned short v_state;         /* vt bitmask */
};
enum { VT_GETSTATE = 0x5603 }; /* get global vt state info */

/* From <linux/serial.h> */
struct serial_struct {
	int	type;
	int	line;
	unsigned int	port;
	int	irq;
	int	flags;
	int	xmit_fifo_size;
	int	custom_divisor;
	int	baud_base;
	unsigned short	close_delay;
	char	io_type;
	char	reserved_char[1];
	int	hub6;
	unsigned short	closing_wait;   /* time to wait before closing */
	unsigned short	closing_wait2;  /* no longer used... */
	unsigned char	*iomem_base;
	unsigned short	iomem_reg_shift;
	unsigned int	port_high;
	unsigned long	iomap_base;	/* cookie passed into ioremap */
	int	reserved[1];
};

ssize_t safe_read(int fd, void *buf, size_t count)
{
        ssize_t n;

        for (;;) {
                n = read(fd, buf, count);
                if (n >= 0 || errno != EINTR)
                        break;
                /* Some callers set errno=0, are upset when they see EINTR.
                 * Returning EINTR is wrong since we retry read(),
                 * the "error" was transient.
                 */
                errno = 0;
                /* repeat the read() */
        }

        return n;
}

/*
 * Read all of the supplied buffer from a file.
 * This does multiple reads as necessary.
 * Returns the amount read, or -1 on an error.
 * A short read is returned on an end of file.
 */
ssize_t full_read(int fd, void *buf, size_t len)
{
        ssize_t cc;
        ssize_t total;

        total = 0;

        while (len) {
                cc = safe_read(fd, buf, len);

                if (cc < 0) {
                        if (total) {
                                /* we already have some! */
                                /* user can do another read to know the error code */
                                return total;
                        }
                        return cc; /* read() returns -1 on failure. */
                }
                if (cc == 0)
                        break;
                buf = ((char *)buf) + cc;
                total += cc;
                len -= cc;
        }

        return total;
}

ssize_t read_close(int fd, void *buf, size_t size)
{
        /*int e;*/
        size = full_read(fd, buf, size);
        /*e = errno;*/
        close(fd);
        /*errno = e;*/
        return size;
}

ssize_t open_read_close(const char *filename, void *buf, size_t size)
{
        int fd = open(filename, O_RDONLY);
        if (fd < 0)
                return fd;
        return read_close(fd, buf, size);
}


/* Like strcpy but can copy overlapping strings. */
void overlapping_strcpy(char *dst, const char *src)
{
        /* Cheap optimization for dst == src case -
         * better to have it here than in many callers.
         */
        if (dst != src) {
                while ((*dst = *src) != '\0') {
                        dst++;
                        src++;
                }
        }
}

// Warn if we can't open a file and return a fd.
int open3_or_warn(const char *pathname, int flags, int mode)
{
        int ret;

        ret = open(pathname, flags, mode);
        if (ret < 0) {
                printf("can't open '%s'", pathname);
        }
        return ret;
}

// Warn if we can't open a file and return a fd.
int open_or_warn(const char *pathname, int flags)
{
        return open3_or_warn(pathname, flags, 0666);
}


void BB_EXECVP_or_die(char **argv)
{
        execvp(argv[0], argv);
        printf("can't execute '%s'", argv[0]);
	exit(2);
}


int main(int argc, char **argv)
{
	int fd;
	char console[sizeof(int)*3 + 16];
	union {
		struct vt_stat vt;
		struct serial_struct sr;
		char paranoia[sizeof(struct serial_struct) * 3];
	} u;

	strcpy(console, "/dev/tty");
	fd = open(console, O_RDWR);
	if (fd < 0) {
		/* We don't have ctty (or don't have "/dev/tty" node...) */
		do {
#ifdef __linux__
			/* Note that this method does not use _stdin_.
			 * Thus, "cttyhack </dev/something" can't be used.
			 * However, this method is more reliable than
			 * TIOCGSERIAL check, which assumes that all
			 * serial lines follow /dev/ttySn convention -
			 * which is not always the case.
			 * Therefore, we use this method first:
			 */
			int s = open_read_close("/sys/class/tty/console/active",
				console + 5, sizeof(console) - 5);
			if (s > 0) {
				char *last;
				/* Found active console via sysfs (Linux 2.6.38+).
				 * It looks like "[tty0 ]ttyS0\n" so zap the newline:
				 */
				console[4 + s] = '\0';
				/* If there are multiple consoles,
				 * take the last one:
				 */
				last = strrchr(console + 5, ' ');
				if (last)
					overlapping_strcpy(console + 5, last + 1);
				break;
			}

			if (ioctl(0, VT_GETSTATE, &u.vt) == 0) {
				/* this is linux virtual tty */
				sprintf(console + 8, "S%u" + 1, (int)u.vt.v_active);
				break;
			}
#endif
#ifdef TIOCGSERIAL
			if (ioctl(0, TIOCGSERIAL, &u.sr) == 0) {
				/* this is a serial console; assuming it is named /dev/ttySn */
				sprintf(console + 8, "S%u", (int)u.sr.line);
				break;
			}
#endif
			/* nope, could not find it */
			console[0] = '\0';
		} while (0);
	}

	argv++;
	if (!argv[0]) {
		if (!console[0])
			return EXIT_FAILURE;
		puts(console);
		return EXIT_SUCCESS;
	}

	if (fd < 0) {
		fd = open_or_warn(console, O_RDWR);
		if (fd < 0)
			goto ret;
	}
	//bb_error_msg("switching to '%s'", console);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	while (fd > 2)
		close(fd--);
	/* Some other session may have it as ctty,
	 * try to steal it from them:
	 */
	ioctl(0, TIOCSCTTY, 1);
 ret:
	BB_EXECVP_or_die(argv);
	return 0;
}
