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

#include <libfam/alloc.H>
#include <libfam/atomic.H>
#include <libfam/connection_internal.H>
#include <libfam/error.H>
#include <libfam/event.H>
#include <libfam/evh.H>
#include <libfam/format.H>
#include <libfam/socket.H>
#include <libfam/sys.H>
#include <libfam/syscall_const.H>

#define MAX_EVENTS 256
#define MIN_CAPACITY 512

#define GCOV_EXIT                        \
	__gcov_dump();                   \
	ASTORE(&evh->stopped, getpid()); \
	exit(0);
#ifdef COVERAGE
void __gcov_dump(void);
#endif /* COVERAGE */

i32 wakeup_attachment = 0;

struct Evh {
	i32 wakeup[2];
	i32 mplex;
	i32 stopped;
	OnRecvFn on_recv;
	OnAcceptFn on_accept;
	OnConnectFn on_connect;
	OnCloseFn on_close;
	void *ctx;
};

STATIC i32 proc_wakeup(i32 wakeup) {
	u8 buf[1];
	i32 v;
	v = read(wakeup, buf, 1);
	if (v <= 0) return -1;
	return 0;
}

STATIC void proc_acceptor(Evh *evh, Connection *acceptor) {
	while (true) {
		Connection *nconn;
		i32 acceptfd = connection_socket(acceptor);
		i32 fd = socket_accept(acceptfd);
		if (fd < 0) {
			if (err != EAGAIN) perror("socket_accept");
			break;
		}

		nconn = connection_accepted(
		    fd, evh->mplex, connection_alloc_overhead(acceptor));
		if (!nconn || evh_register(evh, nconn) < 0) {
			close(fd);
			if (nconn) release(nconn);
			continue;
		}
		evh->on_accept(evh->ctx, nconn);
	}
}

STATIC void proc_close(Evh *evh, Connection *conn) {
	evh->on_close(evh->ctx, conn);
	close(connection_socket(conn));
	connection_release(conn);
}

STATIC i32 check_and_update_rbuf_capacity(Connection *conn) {
	Vec *rbuf = connection_rbuf(conn);
	u64 capacity = vec_capacity(rbuf);
	u64 elements = vec_size(rbuf);
	if (capacity - elements < MIN_CAPACITY) {
		Vec *tmp = vec_resize(rbuf, elements + MIN_CAPACITY);
		if (!tmp) return -1;
		connection_set_rbuf(conn, tmp);
	}
	return 0;
}

STATIC void proc_read(Evh *evh, Connection *conn) {
	i64 rlen = 0;
	i32 socket = connection_socket(conn);
	Vec *rbuf;
	u64 capacity, offset;

	while (true) {
		if (check_and_update_rbuf_capacity(conn) < 0) {
			connection_close(conn);
			break;
		}

		rbuf = connection_rbuf(conn);
		capacity = vec_capacity(rbuf);
		offset = vec_size(rbuf);

		err = 0;
		rlen = read(socket, (u8 *)vec_data(rbuf) + offset,
			    capacity - offset);

		if (rlen <= 0) {
			if (err != EAGAIN) proc_close(evh, conn);
			break;
		}
		vec_set_size(rbuf, offset + rlen);
		evh->on_recv(evh->ctx, conn, rlen);
	}
}

STATIC i32 proc_write(Evh *evh, Connection *conn) {
	i32 sock = connection_socket(conn);
	if (connection_type(conn) == Outbound &&
	    !connection_is_connected(conn)) {
		i32 error = 0;
		i32 len = sizeof(error);
		i32 ret;
		if ((ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &error,
				      &len)) < 0) {
			return -1;
		}
		evh->on_connect(evh->ctx, conn, error);
		connection_set_is_connected(conn);
	}
	return connection_write_complete(conn);
}

STATIC void event_loop(Evh *evh) {
	i32 i, count;
	i32 wakeup = evh->wakeup[0];
	Event events[MAX_EVENTS];

	while (true) {
		count = mwait(evh->mplex, events, MAX_EVENTS, -1);
		for (i = 0; i < count; i++) {
			Connection *conn = event_attachment(events[i]);
			if (conn == (Connection *)&wakeup_attachment) {
				if (proc_wakeup(wakeup) == -1) goto end_while;
			} else {
				if (connection_type(conn) == Acceptor) {
					proc_acceptor(evh, conn);
				} else {
					if (event_is_write(events[i])) {
						proc_write(evh, conn);
					}
					if (event_is_read(events[i])) {
						proc_read(evh, conn);
					}
				}
			}
		}
	}
end_while:
	close(evh->mplex);
	close(wakeup);
#ifdef COVERAGE
	/* dump coverage info before allowing parent to proceed */
	GCOV_EXIT
#else
	ASTORE(&evh->stopped, getpid());
	exit(0);
#endif /* COVERAGE */
}

i32 evh_register(Evh *evh, Connection *conn) {
	i32 socket = connection_socket(conn);
	ConnectionType ctype = connection_type(conn);
	if (ctype == Acceptor) {
		return mregister(evh->mplex, socket, MULTIPLEX_FLAG_ACCEPT,
				 conn);
	} else {
		connection_set_mplex(conn, evh->mplex);
		if (ctype == Outbound && !connection_is_connected(conn)) {
			return mregister(
			    evh->mplex, socket,
			    MULTIPLEX_FLAG_WRITE | MULTIPLEX_FLAG_READ, conn);
		} else {
			if (ctype == Outbound)
				evh->on_connect(evh->ctx, conn, 0);
			return mregister(evh->mplex, socket,
					 MULTIPLEX_FLAG_READ, conn);
		}
	}
}

Evh *evh_init(EvhConfig *config) {
	Evh *ret;
	if (!config || !config->on_recv || !config->on_accept ||
	    !config->on_connect || !config->on_close) {
		err = EINVAL;
		return NULL;
	}
	ret = alloc(sizeof(Evh));
	if (!ret) return NULL;
	ret->mplex = multiplex();
	if (ret->mplex < 0) {
		release(ret);
		return NULL;
	}
	if (pipe(ret->wakeup) < 0) {
		release(ret);
		close(ret->mplex);
		return NULL;
	}
	if (set_nonblocking(ret->wakeup[0]) < 0) {
		release(ret);
		close(ret->mplex);
		close(ret->wakeup[0]);
		close(ret->wakeup[1]);
		return NULL;
	}

	ret->ctx = config->ctx;
	ret->on_recv = config->on_recv;
	ret->on_accept = config->on_accept;
	ret->on_connect = config->on_connect;
	ret->on_close = config->on_close;
	ret->stopped = 0;

	return ret;
}
i32 evh_start(Evh *evh) {
	i32 pid;

	if (mregister(evh->mplex, evh->wakeup[0], MULTIPLEX_FLAG_READ,
		      &wakeup_attachment) == -1) {
		return -1;
	}

	pid = two();
	if (pid < 0) return -1;
	if (pid == 0) event_loop(evh);

	return 0;
}

i32 evh_stop(Evh *evh) {
	if (ALOAD(&evh->stopped)) {
		err = EALREADY;
		return -1;
	}
	close(evh->wakeup[1]);
	while (!ALOAD(&evh->stopped)) yield();
	return waitid(P_PID, evh->stopped, NULL, WEXITED);
}
void evh_destroy(Evh *evh) { release(evh); }

