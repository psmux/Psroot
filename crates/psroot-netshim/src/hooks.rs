//! Winsock hook implementations.
//!
//! Each hook is `extern "system"` with exactly the ABI of its ws2_32
//! counterpart. On entry we check [`state::is_bypassed`]; if set (e.g.
//! the daemon thread is itself performing real socket I/O), we forward
//! directly to the original function pointer captured during IAT
//! patching. Otherwise we translate the call to a request on the
//! [`Client`] and return the result with the correct Winsock error code.

#![cfg(windows)]

use core::ffi::c_int;
use core::sync::atomic::Ordering;

use psroot_netstack_proto::{SockAddrBytes, StatusCode, AF_INET_V};
use windows_sys::Win32::Networking::WinSock::{
    SOCKADDR, SOCKADDR_IN, SOCKET, SOCK_DGRAM, SOCK_STREAM, WSASetLastError, INVALID_SOCKET, SOCKET_ERROR,
    WSAECONNABORTED, WSAECONNREFUSED, WSAECONNRESET, WSAEFAULT, WSAEINVAL, WSAENOBUFS,
    WSAENOTCONN, WSAENOTSOCK, WSAEWOULDBLOCK, AF_INET,
};

use crate::client::ClientError;
use crate::state::{is_bypassed, BypassGuard, STATE};

// ─────────────────── ABI-exact function pointer types ──────────────────

type FnSocket = unsafe extern "system" fn(c_int, c_int, c_int) -> SOCKET;
type FnConnect = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
type FnSend = unsafe extern "system" fn(SOCKET, *const u8, c_int, c_int) -> c_int;
type FnRecv = unsafe extern "system" fn(SOCKET, *mut u8, c_int, c_int) -> c_int;
type FnClose = unsafe extern "system" fn(SOCKET) -> c_int;
type FnBind = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
type FnListen = unsafe extern "system" fn(SOCKET, c_int) -> c_int;
type FnGetName = unsafe extern "system" fn(SOCKET, *mut SOCKADDR, *mut c_int) -> c_int;
type FnSendTo = unsafe extern "system" fn(SOCKET, *const u8, c_int, c_int, *const SOCKADDR, c_int) -> c_int;
type FnRecvFrom =
    unsafe extern "system" fn(SOCKET, *mut u8, c_int, c_int, *mut SOCKADDR, *mut c_int) -> c_int;

// ─────────────────────────── hook bodies ───────────────────────────────

pub unsafe extern "system" fn hook_socket(af: c_int, typ: c_int, proto: c_int) -> SOCKET {
    if is_bypassed() {
        return call_real_socket(af, typ, proto);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_socket(af, typ, proto);
    };
    // Route both SOCK_STREAM (TCP) and SOCK_DGRAM (UDP, Phase 3) over
    // the netstack. Everything else (SOCK_RAW, etc.) still goes
    // straight to the OS stack.
    if af != AF_INET as c_int
        || (typ != SOCK_STREAM as c_int && typ != SOCK_DGRAM as c_int)
    {
        return call_real_socket(af, typ, proto);
    }
    match state.client.socket(AF_INET_V, typ as u16, proto as u32) {
        Ok(virt) => state.alloc_fake(virt),
        Err(_) => {
            WSASetLastError(WSAENOBUFS);
            INVALID_SOCKET
        }
    }
}

pub unsafe extern "system" fn hook_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_connect(s, name, namelen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_connect(s, name, namelen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_connect(s, name, namelen);
    };
    let Some(addr) = sockaddr_from_raw(name, namelen) else {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    };
    match state.client.connect(virt, addr) {
        Ok(()) => 0,
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_bind(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_bind(s, name, namelen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_bind(s, name, namelen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_bind(s, name, namelen);
    };
    let Some(addr) = sockaddr_from_raw(name, namelen) else {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    };
    match state.client.bind(virt, addr) {
        Ok(()) => 0,
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_listen(s: SOCKET, backlog: c_int) -> c_int {
    if is_bypassed() {
        return call_real_listen(s, backlog);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_listen(s, backlog);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_listen(s, backlog);
    };
    match state.client.listen(virt, backlog.max(0) as u32) {
        Ok(()) => 0,
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_send(
    s: SOCKET,
    buf: *const u8,
    len: c_int,
    _flags: c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_send(s, buf, len, _flags);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_send(s, buf, len, _flags);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_send(s, buf, len, _flags);
    };
    if len < 0 || buf.is_null() {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let slice = core::slice::from_raw_parts(buf, len as usize);
    // The daemon's wire protocol caps payloads at DATA_CAPACITY; send
    // just the first chunk and report how many bytes we actually posted
    // (matches Winsock partial-write semantics).
    let chunk =
        &slice[..slice.len().min(psroot_netstack_proto::DATA_CAPACITY)];
    match state.client.send(virt, chunk) {
        Ok(n) => n as c_int,
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_recv(
    s: SOCKET,
    buf: *mut u8,
    len: c_int,
    _flags: c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_recv(s, buf, len, _flags);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_recv(s, buf, len, _flags);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_recv(s, buf, len, _flags);
    };
    if len <= 0 || buf.is_null() {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    match state.client.recv(virt, len as u32) {
        Ok(data) => {
            let n = data.len().min(len as usize);
            if n > 0 {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buf, n);
            }
            n as c_int
        }
        Err(ClientError::Status(StatusCode::WouldBlock)) => {
            WSASetLastError(WSAEWOULDBLOCK);
            SOCKET_ERROR
        }
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_closesocket(s: SOCKET) -> c_int {
    if is_bypassed() {
        return call_real_closesocket(s);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_closesocket(s);
    };
    let Some(virt) = state.forget(s) else {
        return call_real_closesocket(s);
    };
    match state.client.close(virt) {
        Ok(()) => 0,
        Err(_) => 0, // best-effort; the fake handle is already gone
    }
}

pub unsafe extern "system" fn hook_getsockname(
    s: SOCKET,
    name: *mut SOCKADDR,
    namelen: *mut c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_getsockname(s, name, namelen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_getsockname(s, name, namelen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_getsockname(s, name, namelen);
    };
    match state.client.getsockname(virt) {
        Ok(addr) => write_sockaddr(&addr, name, namelen),
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_getpeername(
    s: SOCKET,
    name: *mut SOCKADDR,
    namelen: *mut c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_getpeername(s, name, namelen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_getpeername(s, name, namelen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_getpeername(s, name, namelen);
    };
    match state.client.getpeername(virt) {
        Ok(addr) => write_sockaddr(&addr, name, namelen),
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_sendto(
    s: SOCKET,
    buf: *const u8,
    len: c_int,
    flags: c_int,
    to: *const SOCKADDR,
    tolen: c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_sendto(s, buf, len, flags, to, tolen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_sendto(s, buf, len, flags, to, tolen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_sendto(s, buf, len, flags, to, tolen);
    };
    if len < 0 || buf.is_null() {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let Some(addr) = sockaddr_from_raw(to, tolen) else {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    };
    let slice = core::slice::from_raw_parts(buf, len as usize);
    // UDP datagrams must fit in a single slot payload minus the
    // 28-byte sockaddr prefix the wire protocol prepends.
    let max_dgram = psroot_netstack_proto::DATA_CAPACITY - 28;
    let chunk = &slice[..slice.len().min(max_dgram)];
    match state.client.sendto(virt, addr, chunk) {
        Ok(n) => n as c_int,
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

pub unsafe extern "system" fn hook_recvfrom(
    s: SOCKET,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
    from: *mut SOCKADDR,
    fromlen: *mut c_int,
) -> c_int {
    if is_bypassed() {
        return call_real_recvfrom(s, buf, len, flags, from, fromlen);
    }
    let _g = BypassGuard::enter();
    let Some(state) = STATE.get() else {
        return call_real_recvfrom(s, buf, len, flags, from, fromlen);
    };
    let Some(virt) = state.lookup(s) else {
        return call_real_recvfrom(s, buf, len, flags, from, fromlen);
    };
    if len <= 0 || buf.is_null() {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    match state.client.recvfrom(virt, len as u32) {
        Ok((data, peer)) => {
            let n = data.len().min(len as usize);
            if n > 0 {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buf, n);
            }
            // `from` is optional \u2014 callers can pass null to ignore it.
            if !from.is_null() && !fromlen.is_null() {
                // Best-effort address write; failure here is non-fatal,
                // we still return the bytes received.
                let _ = write_sockaddr(&peer, from, fromlen);
            }
            n as c_int
        }
        Err(ClientError::Status(StatusCode::WouldBlock)) => {
            WSASetLastError(WSAEWOULDBLOCK);
            SOCKET_ERROR
        }
        Err(e) => {
            WSASetLastError(status_to_wsa(&e));
            SOCKET_ERROR
        }
    }
}

// ─────────────────── passthrough to captured originals ─────────────────

/// Load a captured original function pointer from [`ShimState`]. Returns
/// `None` when no original has been recorded (IAT patching hasn't run
/// for this symbol yet, or this module was loaded without installing
/// hooks).
#[inline(always)]
fn load_original(slot: &core::sync::atomic::AtomicUsize) -> Option<usize> {
    match slot.load(Ordering::Acquire) {
        0 => None,
        v => Some(v),
    }
}

unsafe fn call_real_socket(af: c_int, typ: c_int, proto: c_int) -> SOCKET {
    if let Some(p) = STATE.get().and_then(|s| load_original(&s.originals.socket)) {
        let f: FnSocket = core::mem::transmute(p);
        f(af, typ, proto)
    } else {
        WSASetLastError(WSAEINVAL);
        INVALID_SOCKET
    }
}
unsafe fn call_real_connect(s: SOCKET, n: *const SOCKADDR, l: c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.connect)) {
        let f: FnConnect = core::mem::transmute(p);
        f(s, n, l)
    } else {
        WSASetLastError(WSAEINVAL);
        SOCKET_ERROR
    }
}
unsafe fn call_real_bind(s: SOCKET, n: *const SOCKADDR, l: c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.bind)) {
        let f: FnBind = core::mem::transmute(p);
        f(s, n, l)
    } else {
        WSASetLastError(WSAEINVAL);
        SOCKET_ERROR
    }
}
unsafe fn call_real_listen(s: SOCKET, b: c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.listen)) {
        let f: FnListen = core::mem::transmute(p);
        f(s, b)
    } else {
        WSASetLastError(WSAEINVAL);
        SOCKET_ERROR
    }
}
unsafe fn call_real_send(s: SOCKET, b: *const u8, l: c_int, f: c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.send)) {
        let ff: FnSend = core::mem::transmute(p);
        ff(s, b, l, f)
    } else {
        WSASetLastError(WSAENOTCONN);
        SOCKET_ERROR
    }
}
unsafe fn call_real_recv(s: SOCKET, b: *mut u8, l: c_int, f: c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.recv)) {
        let ff: FnRecv = core::mem::transmute(p);
        ff(s, b, l, f)
    } else {
        WSASetLastError(WSAENOTCONN);
        SOCKET_ERROR
    }
}
unsafe fn call_real_closesocket(s: SOCKET) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.closesocket)) {
        let f: FnClose = core::mem::transmute(p);
        f(s)
    } else {
        0
    }
}
unsafe fn call_real_getsockname(s: SOCKET, n: *mut SOCKADDR, l: *mut c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.getsockname)) {
        let f: FnGetName = core::mem::transmute(p);
        f(s, n, l)
    } else {
        WSASetLastError(WSAENOTSOCK);
        SOCKET_ERROR
    }
}
unsafe fn call_real_getpeername(s: SOCKET, n: *mut SOCKADDR, l: *mut c_int) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.getpeername)) {
        let f: FnGetName = core::mem::transmute(p);
        f(s, n, l)
    } else {
        WSASetLastError(WSAENOTSOCK);
        SOCKET_ERROR
    }
}
unsafe fn call_real_sendto(
    s: SOCKET,
    b: *const u8,
    l: c_int,
    f: c_int,
    to: *const SOCKADDR,
    tl: c_int,
) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.sendto)) {
        let ff: FnSendTo = core::mem::transmute(p);
        ff(s, b, l, f, to, tl)
    } else {
        WSASetLastError(WSAENOTCONN);
        SOCKET_ERROR
    }
}
unsafe fn call_real_recvfrom(
    s: SOCKET,
    b: *mut u8,
    l: c_int,
    f: c_int,
    from: *mut SOCKADDR,
    fl: *mut c_int,
) -> c_int {
    if let Some(p) = STATE.get().and_then(|st| load_original(&st.originals.recvfrom)) {
        let ff: FnRecvFrom = core::mem::transmute(p);
        ff(s, b, l, f, from, fl)
    } else {
        WSASetLastError(WSAENOTCONN);
        SOCKET_ERROR
    }
}

// ──────────────────────────── conversions ──────────────────────────────

unsafe fn sockaddr_from_raw(name: *const SOCKADDR, len: c_int) -> Option<SockAddrBytes> {
    if name.is_null() || len < core::mem::size_of::<SOCKADDR_IN>() as c_int {
        return None;
    }
    let family = (*name).sa_family;
    if family != AF_INET {
        return None;
    }
    let sin = &*(name as *const SOCKADDR_IN);
    // sin_port / sin_addr are in network byte order.
    let port = u16::from_be(sin.sin_port);
    let raw = sin.sin_addr.S_un.S_addr;
    let octets = raw.to_ne_bytes(); // already network order = [a, b, c, d]
    Some(SockAddrBytes::v4(octets, port))
}

unsafe fn write_sockaddr(
    addr: &SockAddrBytes,
    out: *mut SOCKADDR,
    out_len: *mut c_int,
) -> c_int {
    if out.is_null() || out_len.is_null() {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let needed = core::mem::size_of::<SOCKADDR_IN>() as c_int;
    if *out_len < needed {
        *out_len = needed;
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let sin = out as *mut SOCKADDR_IN;
    (*sin).sin_family = AF_INET;
    (*sin).sin_port = addr.port.to_be();
    // First four bytes of addr are the v4 octets.
    let mut raw_bytes = [0u8; 4];
    raw_bytes.copy_from_slice(&addr.addr[..4]);
    (*sin).sin_addr.S_un.S_addr = u32::from_ne_bytes(raw_bytes);
    // Zero out padding.
    (*sin).sin_zero = [0; 8];
    *out_len = needed;
    0
}

fn status_to_wsa(e: &ClientError) -> i32 {
    match e {
        ClientError::Status(StatusCode::ConnRefused) => WSAECONNREFUSED,
        ClientError::Status(StatusCode::ConnReset) => WSAECONNRESET,
        ClientError::Status(StatusCode::WouldBlock) => WSAEWOULDBLOCK,
        ClientError::Status(StatusCode::BadSocket) => WSAENOTSOCK,
        ClientError::Status(StatusCode::NotSupported) => WSAEINVAL,
        ClientError::Status(StatusCode::AddrInUse) => 10048,     // WSAEADDRINUSE
        ClientError::Status(StatusCode::AddrNotAvail) => 10049,  // WSAEADDRNOTAVAIL
        ClientError::Status(_) => WSAECONNABORTED,
        _ => WSAECONNABORTED,
    }
}
