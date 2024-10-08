	/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

void lock_donate (struct thread *t, struct lock *lock) {
	ASSERT (intr_get_level () == INTR_OFF);

	struct thread * holder = lock->holder;
		
	if (t->priority <= holder->priority)
		return;
	
	holder->priority = t->priority;
	if (holder->failed_lock)
		lock_donate (holder, holder->failed_lock);
}

void thread_add_lock (struct thread *t, struct lock *lock) {	
	ASSERT (intr_get_level () == INTR_OFF);
	
	t->locks[t->lock_count++] = lock;
}

void thread_remove_lock (struct thread *t, struct lock *lock) {
	ASSERT (intr_get_level () == INTR_OFF);
	
	for (int i = 0; i < t->lock_count; i++) {
		if (t->locks[i] == lock) {
			for (int j = i; j < t->lock_count - 1; j++)
				t->locks[j] = t->locks[j+1];
			t->locks[--t->lock_count] = NULL;
			break;
		}
	}
}

/*	
void lock_donate_acq (struct thread *t, struct lock *lock) {
	ASSERT (intr_get_level () == INTR_OFF);
	enum intr_level old_level;
	// old_level = intr_disable ();
	struct thread * holder = lock->holder;
	if (t->priority > holder->priority) {
		holder->priority = t->priority;
	}
	else
		return;

	for (int i = 0; i < holder->lock_count; i++) 
		lock_donate_acq (lock->holder, holder->locks[i]);

}*/
/*
void lock_donate_rel (struct thread *t) {
	ASSERT (intr_get_level () == INTR_OFF);

	int prio = t->prio_orig;

	for (int i = 0; i < t->lock_count; i++) {
		struct lock *idx = t->locks[i];
		if (t != idx->holder || list_empty (&idx->semaphore.waiters))
			continue;

		int idx_prio = list_entry (list_max (&idx->semaphore.waiters, priority_more, NULL), struct thread, elem)->priority;
		if (prio < idx_prio)
			prio = idx_prio;
	}

	t->priority = prio;

	for (int i = 0; i < t->lock_count; i++) {
		struct lock *idx = t->locks[i];

		if (t != idx->holder)
			lock_donate_rel (idx->holder);
	}*/
	/*
	for (e = list_begin (&t->locks); e != list_end (&t->locks); e = list_next(e)) {
		struct lock *idx = list_entry (e, struct lock_list_elem, elem)->lock;

		if (t != idx->holder || list_empty (&idx->semaphore.waiters))
			continue;

		int idx_prio = list_entry (list_max (&idx->semaphore.waiters, priority_more, NULL), struct thread, elem)->priority;
		if (prio < idx_prio)
			prio = idx_prio;
	}
	t->priority = prio;

	for (e = list_begin (&t->locks); e != list_end (&t->locks); e = list_next(e)) {
		struct lock *idx = list_entry (e, struct lock_list_elem, elem)->lock;

		if (t != idx->holder)
			lock_donate_rel (idx->holder);
	}
}*/


/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		list_push_back (&sema->waiters, &thread_current ()->elem);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	
	if (!list_empty (&sema->waiters)) {
		struct list_elem *e = list_max (&sema->waiters, priority_less, NULL);		
		struct thread *t = list_entry (e, struct thread, elem);
		list_remove(e);

		thread_unblock (t);
	}
	sema->value++;
	thread_check ();
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	enum intr_level old_level;

	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	old_level = intr_disable ();

	thread_add_lock (thread_current (), lock);

	if (!lock_try_acquire (lock)) {
		ASSERT (thread_current ()->failed_lock == NULL);
		thread_current ()->failed_lock = lock;
		lock_donate (thread_current (), lock);
		sema_down (&lock->semaphore);
	}
	intr_set_level (old_level);

	// sema_down (&lock->semaphore);
	// lock->holder = thread_current ();
}

bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

void lock_release (struct lock *lock) {
	enum intr_level old_level;
	struct thread *curr = thread_current ();

	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	// printf("%d:lock_release\n", thread_current()->name);
	old_level = intr_disable ();
	
	thread_remove_lock (thread_current (), lock);
	
	int prio = curr->prio_orig;

	for (int i = 0; i < curr->lock_count; i++) {
		struct lock *idx = curr->locks[i];
		if (list_empty (&idx->semaphore.waiters))
			continue;

		int idx_prio = list_entry (list_max (&idx->semaphore.waiters, priority_more, NULL), struct thread, elem)->priority;
		if (prio < idx_prio)
			prio = idx_prio;
	}
	curr->priority = prio;

	if (list_empty (&lock->semaphore.waiters)) 
		lock->holder = NULL;
	else {
		struct list_elem *e = list_max (&lock->semaphore.waiters, priority_less, NULL);
		lock->holder = list_entry (e, struct thread, elem);
		ASSERT (lock->holder->failed_lock == lock);
		lock->holder->failed_lock = NULL;
	}

	sema_up (&lock->semaphore);
	intr_set_level (old_level);
	// lock->holder = NULL;
	// sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
	int priority;
};

bool
sema_priority_less (const struct list_elem *a_, const struct list_elem *b_,
		void *aux UNUSED)
{
	const struct semaphore_elem *a = list_entry (a_, struct semaphore_elem, elem);
	const struct semaphore_elem *b = list_entry (b_, struct semaphore_elem, elem);

	return a->priority < b->priority;
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	waiter.priority = thread_get_priority ();
	list_push_back (&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)) {
		struct list_elem *e = list_max (&cond->waiters, sema_priority_less, NULL);
		struct semaphore_elem *se = list_entry (e, struct semaphore_elem, elem);
		list_remove (e);
		sema_up (&se->semaphore);
		// sema_up (&list_entry (list_pop_front (&cond->waiters),
		// 			struct semaphore_elem, elem)->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}