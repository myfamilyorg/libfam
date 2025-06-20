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

#include <alloc.H>
#include <error.H>
#include <event.H>
#include <evh.H>
#include <lock.H>
#include <misc.H>
#include <socket.H>
#include <syscall.H>
#include <syscall_const.H>

bool debug_force_write_buffer = 0;

Connection *evh_acceptor(u8 addr[4], u16 port, u16 backlog,
			 OnRecvFn on_recv_fn, OnAcceptFn on_accept_fn,
			 OnCloseFn on_close_fn) {
	i32 pval;
	Connection *conn = alloc(sizeof(Connection));
	if (conn == NULL) return NULL;
	conn->conn_type = Acceptor;
	conn->data.acceptor.on_accept = on_accept_fn;
	conn->data.acceptor.on_recv = on_recv_fn;
	conn->data.acceptor.on_close = on_close_fn;
	pval = socket_listen(&conn->socket, addr, port, backlog);
	if (pval == -1) {
		release(conn);
		return NULL;
	}
	conn->data.acceptor.port = pval;
	return conn;
}
u16 evh_acceptor_port(Connection *conn) {
	if (conn->conn_type == Acceptor) return conn->data.acceptor.port;
	err = EINVAL;
	return 0;
}

Connection *evh_client(u8 addr[4], u16 port, OnRecvFn on_recv_fn,
		       OnCloseFn on_close_fn,
		       u64 connection_alloc_overhead) {
	Connection *client =
	    alloc(sizeof(Connection) + connection_alloc_overhead);
	if (client == NULL) return NULL;
	client->conn_type = Outbound;
	client->data.inbound.on_recv = on_recv_fn;
	client->data.inbound.on_close = on_close_fn;
	client->data.inbound.lock = LOCK_INIT;
	client->data.inbound.is_closed = false;
	client->data.inbound.rbuf = NULL;
	client->data.inbound.rbuf_capacity = 0;
	client->data.inbound.rbuf_offset = 0;
	client->data.inbound.wbuf = NULL;
	client->data.inbound.wbuf_capacity = 0;
	client->data.inbound.wbuf_offset = 0;
	client->socket = socket_connect(addr, port);
	if (client->socket == -1) {
		release(client);
		return NULL;
	}
	return client;
}

i32 connection_close(Connection *connection) {
	if (connection->conn_type == Acceptor) {
		return close(connection->socket);
	} else {
		LockGuard lg = wlock(&connection->data.inbound.lock);
		InboundData *ib = &connection->data.inbound;
		if (ib->is_closed) return -1;
		ib->is_closed = true;
		return shutdown(connection->socket, SHUT_RDWR);
	}
}

i32 connection_write(Connection *connection, const void *buf, u64 len) {
	i64 wlen = 0;
	InboundData *ib = &connection->data.inbound;
	LockGuard lg = wlock(&ib->lock);
	if (ib->is_closed) return -1;
	if (!ib->wbuf_offset) {
		u64 offset = 0;
	write_block:
		err = 0;
		if (debug_force_write_buffer)
			wlen = 0;
		else
			wlen = write(connection->socket,
				     (u8 *)buf + offset, len);
		if (err == EINTR) {
			if (wlen > 0) offset += wlen;
			goto write_block;
		} else if (err == EAGAIN)
			wlen = 0; /* Set for other logic */
		else if (err) {	  /* shutdown for other errors */
			shutdown(connection->socket, SHUT_RDWR);
			ib->is_closed = true;
			return -1;
		}

		if ((u64)wlen == len) return 0;
		if (mregister(ib->mplex, connection->socket,
			      MULTIPLEX_FLAG_READ | MULTIPLEX_FLAG_WRITE,
			      connection) == -1) {
			shutdown(connection->socket, SHUT_RDWR);
			ib->is_closed = true;
			return -1;
		}
	}

	if (ib->wbuf_offset + len - wlen > ib->wbuf_capacity) {
		void *tmp = resize(ib->wbuf, ib->wbuf_offset + len - wlen);
		if (!tmp) {
			shutdown(connection->socket, SHUT_RDWR);
			ib->is_closed = true;
			return -1;
		}
		ib->wbuf = tmp;
		ib->wbuf_capacity = ib->wbuf_offset + len - wlen;
	}
	memcpy(ib->wbuf + ib->wbuf_offset, (u8 *)buf + wlen, len - wlen);
	ib->wbuf_offset += len - wlen;

	return 0;
}

void connection_clear_rbuf_through(Connection *conn, u64 off) {
	InboundData *ib = &conn->data.inbound;
	if (off > ib->rbuf_offset) return;
	memorymove(ib->rbuf, ib->rbuf + off, ib->rbuf_offset - off);
	ib->rbuf_offset -= off;
}

void connection_clear_rbuf(Connection *conn) {
	InboundData *ib = &conn->data.inbound;
	ib->rbuf_offset = 0;
}
