/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#include <libfam/error.H>
#include <libfam/format.H>
#include <libfam/lock.H>
#include <libfam/robust.H>

typedef unsigned int pthread_key_t;
typedef int pthread_mutexattr_t;
typedef u32 pthread_mutex_t;
typedef unsigned int pthread_t;

void *pthread_getspecific(pthread_key_t key __attribute__((unused))) {
	panic("Unexpected call with MDB_NOTLS");
	return NULL;
}

int pthread_key_delete(pthread_key_t key __attribute__((unused))) {
	panic("Unexpected call with MDB_NOTLS");
	return -1;
}

int pthread_key_create(pthread_key_t *key __attribute__((unused)),
		       void (*destructor)(void *) __attribute__((unused))) {
	panic("Unexpected call with MDB_NOTLS");
	return -1;
}

int pthread_setspecific(pthread_key_t key __attribute__((unused)),
			const void *value __attribute__((unused))) {
	panic("Unexpected call with MDB_NOTLS");
	return -1;
}

int pthread_mutexattr_setrobust(pthread_mutexattr_t *attr
				__attribute__((unused))) {
	return 0;
}

int pthread_mutex_consistent(pthread_mutexattr_t *attr
			     __attribute__((unused))) {
	return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr
			      __attribute__((unused))) {
	return 0;
}

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr
				 __attribute__((unused)),
				 int pshared __attribute__((unused))) {
	return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
	if (attr) *attr = 0;
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex __attribute__((unused))) {
	err = SUCCESS;
	RobustGuardImpl lg __attribute__((unused)) = robust_lock(mutex);
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex __attribute__((unused))) {
	RobustGuardImpl lg;
	lg.lock = mutex;
	robustguard_cleanup(&lg);
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr
		       __attribute__((unused))) {
	if (mutex) *mutex = LOCK_INIT;
	return 0;
}

pthread_t pthread_self(void) { return 0; }

LockGuardImpl pthread_mutex_lock_guard(pthread_mutex_t *mutex) {
	LockGuardImpl ret = wlock(mutex);
	return ret;
}
