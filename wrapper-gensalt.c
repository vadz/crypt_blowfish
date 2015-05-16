/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2011.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2011 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 */

#include <stdlib.h>
#include <string.h>

#include <errno.h>
#ifndef __set_errno
#define __set_errno(val) errno = (val)
#endif

#define CRYPT_GENSALT_OUTPUT_SIZE	(7 + 22 + 1)

#if defined(__GLIBC__) && defined(_LIBC)
#define __SKIP_GNU
#endif
#include "ow-crypt.h"

#include "crypt_gensalt.h"

#if !(defined(__GLIBC__) && defined(_LIBC))
#define __crypt_gensalt_rn crypt_gensalt_rn
#define __crypt_gensalt_ra crypt_gensalt_ra
#define __crypt_gensalt crypt_gensalt
#endif

char *__crypt_gensalt_rn(const char *prefix, unsigned long count,
	const char *input, int size, char *output, int output_size)
{
	char *(*use)(const char *_prefix, unsigned long _count,
		const char *_input, int _size,
		char *_output, int _output_size);

	/* This may be supported on some platforms in the future */
	if (!input) {
		__set_errno(EINVAL);
		return NULL;
	}

	if (!strncmp(prefix, "$5$", 3) || !strncmp(prefix, "$6$", 3))
		use = _crypt_gensalt_sha2_rn;
	else
	if (!strncmp(prefix, "$2a$", 4) || !strncmp(prefix, "$2b$", 4) ||
	    !strncmp(prefix, "$2y$", 4))
		use = _crypt_gensalt_blowfish_rn;
	else
	if (!strncmp(prefix, "$1$", 3))
		use = _crypt_gensalt_md5_rn;
	else
	if (prefix[0] == '_')
		use = _crypt_gensalt_extended_rn;
	else
	if (!prefix[0] ||
	    (prefix[0] && prefix[1] &&
	    memchr(_crypt_itoa64, prefix[0], 64) &&
	    memchr(_crypt_itoa64, prefix[1], 64)))
		use = _crypt_gensalt_traditional_rn;
	else {
		__set_errno(EINVAL);
		return NULL;
	}

	return use(prefix, count, input, size, output, output_size);
}

char *__crypt_gensalt_ra(const char *prefix, unsigned long count,
	const char *input, int size)
{
	char output[CRYPT_GENSALT_OUTPUT_SIZE];
	char *retval;

	retval = __crypt_gensalt_rn(prefix, count,
		input, size, output, sizeof(output));

	if (retval) {
		retval = strdup(retval);
#ifndef __GLIBC__
		/* strdup(3) on glibc sets errno, so we don't need to bother */
		if (!retval)
			__set_errno(ENOMEM);
#endif
	}

	return retval;
}

char *__crypt_gensalt(const char *prefix, unsigned long count,
	const char *input, int size)
{
	static char output[CRYPT_GENSALT_OUTPUT_SIZE];

	return __crypt_gensalt_rn(prefix, count,
		input, size, output, sizeof(output));
}

#if defined(__GLIBC__) && defined(_LIBC)
weak_alias(__crypt_gensalt_rn, crypt_gensalt_rn)
weak_alias(__crypt_gensalt_ra, crypt_gensalt_ra)
weak_alias(__crypt_gensalt, crypt_gensalt)
#endif
