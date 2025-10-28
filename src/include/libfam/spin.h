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

#ifndef _SPIN_LOCK_H
#define _SPIN_LOCK_H

#include <libfam/types.h>

/*
 * Constant: SPINLOCK_INIT
 * Initializer for a SpinLock in unlocked state.
 * notes:
 *         Use as: SpinLock lock = SPINLOCK_INIT;
 *         Equivalent to { .value = 0 }.
 *         Must be used at file or global scope (static storage).
 */
#define SPINLOCK_INIT *(&(SpinLock){.value = 0})

/*
 * Type: SpinLock
 * Simple ticket-based spinlock using atomic exchange.
 * members:
 *         u32 value - current ticket counter (0 = unlocked).
 * notes:
 *         Uses __aadd32 internally for atomic increment.
 *         Fair (FIFO) acquisition order.
 *         No recursion support.
 *         Suitable for short critical sections only.
 */
typedef struct {
	u32 value;
} SpinLock;

/*
 * Function: spin_lock
 * Acquires the spinlock, blocking until available.
 * inputs:
 *         SpinLock *lock - pointer to initialized spinlock.
 * return value: None.
 * errors: None.
 * notes:
 *         lock must not be null.
 *         Spins using __aadd32 to atomically increment ticket.
 *         Waits until current ticket matches served ticket.
 *         High CPU usage under contention — avoid long holds.
 *         Reentrant calls cause deadlock.
 */
void spin_lock(SpinLock *lock);

/*
 * Function: spin_unlock
 * Releases the spinlock.
 * inputs:
 *         SpinLock *lock - pointer to acquired spinlock.
 * return value: None.
 * errors: None.
 * notes:
 *         lock must not be null.
 *         Must be called by the thread that acquired it.
 *         Uses __aadd32 to advance the served ticket.
 *         Undefined behavior if called on unlocked lock.
 */
void spin_unlock(SpinLock *lock);

#endif /* _SPIN_LOCK_H */
