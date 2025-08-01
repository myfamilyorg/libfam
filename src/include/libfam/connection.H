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

#ifndef _CONNECTION_H
#define _CONNECTION_H

#include <libfam/types.H>
#include <libfam/vec.H>

#define CONN_FLAG_ACCEPTOR (0x1 << 0)
#define CONN_FLAG_INBOUND (0x1 << 1)
#define CONN_FLAG_OUTBOUND (0x1 << 2)
#define CONN_FLAG_CLOSED (0x1 << 3)
#define CONN_FLAG_CONNECT_COMPLETE (0x1 << 4)
#define CONN_FLAG_USR1 (0x1 << 5)
#define CONN_FLAG_USR2 (0x1 << 6)

typedef enum { Acceptor, Inbound, Outbound } ConnectionType;
typedef struct Connection Connection;

typedef void (*OnRecvFn)(void *ctx, Connection *conn, u64 rlen);
typedef void (*OnAcceptFn)(void *ctx, Connection *conn);
typedef void (*OnCloseFn)(void *ctx, Connection *conn);
typedef void (*OnConnectFn)(void *ctx, Connection *conn, i32 error);

Connection *connection_acceptor(const u8 addr[4], u16 port, u16 backlog,
				u32 connection_alloc_overhead);
Connection *connection_client(const u8 addr[4], u16 port,
			      u32 connection_alloc_overhead);

i32 connection_acceptor_port(const Connection *conn);
i32 connection_close(Connection *connection);
i32 connection_write(Connection *connection, const void *buf, u64 len);
Vec *connection_rbuf(Connection *conn);
Vec *connection_wbuf(Connection *conn);
void connection_set_rbuf(Connection *conn, Vec *v);
ConnectionType connection_type(Connection *conn);
i32 connection_socket(Connection *conn);
bool connection_is_closed(Connection *conn);
bool connection_is_connected(Connection *conn);
void connection_set_flag(Connection *conn, u32 flag, bool value);
bool connection_get_flag(Connection *conn, u32 flag);
void connection_set_flag_upper_bits(Connection *conn, u16 upper);
u16 connection_get_flag_upper_bits(Connection *conn);
u64 connection_size(void);
void connection_release(Connection *conn);

#endif /* _CONNECTION_H */
