/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#ifdef ZMQ_HAVE_OPENPGM

#ifdef ZMQ_HAVE_LINUX
#include <poll.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <string>

#include "options.hpp"
#include "pgm_socket.hpp"
#include "config.hpp"
#include "err.hpp"
#include "random.hpp"
#include "stdint.hpp"

#ifndef MSG_ERRQUEUE
#define MSG_ERRQUEUE 0x2000
#endif

zmq::pgm_socket_t::pgm_socket_t (bool receiver_, const options_t &options_) :
    sock (NULL),
    options (options_),
    receiver (receiver_),
    pgm_msgv (NULL),
    pgm_msgv_len (0),
    nbytes_rec (0),
    nbytes_processed (0),
    pgm_msgv_processed (0)
{
}

//  Resolve PGM socket address.
//  network_ of the form <interface & multicast group decls>:<IP port>
//  e.g. eth0;239.192.0.1:7500
//       link-local;224.250.0.1,224.250.0.2;224.250.0.3:8000
//       ;[fe80::1%en0]:7500
int zmq::pgm_socket_t::init_address (const char *network_,
                                     struct pgm_addrinfo_t **res,
                                     uint16_t *port_number)
{
    //  Parse port number, start from end for IPv6
    const char *port_delim = strrchr (network_, ':');
    if (!port_delim) {
        errno = EINVAL;
        return -1;
    }

    *port_number = atoi (port_delim + 1);

    char network[256];
    if (port_delim - network_ >= (int) sizeof (network) - 1) {
        errno = EINVAL;
        return -1;
    }
    memset (network, '\0', sizeof (network));
    memcpy (network, network_, port_delim - network_);

    pgm_error_t *pgm_error = NULL;
    struct pgm_addrinfo_t hints;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    if (!pgm_getaddrinfo (network, NULL, res, &pgm_error)) {
        //  Invalid parameters don't set pgm_error_t.
        zmq_assert (pgm_error != NULL);
        if (pgm_error->domain == PGM_ERROR_DOMAIN_IF &&

            //  NB: cannot catch EAI_BADFLAGS.
            (pgm_error->code != PGM_ERROR_SERVICE
             && pgm_error->code != PGM_ERROR_SOCKTNOSUPPORT)) {
            //  User, host, or network configuration or transient error.
            pgm_error_free (pgm_error);
            errno = EINVAL;
            return -1;
        }

        //  Fatal OpenPGM internal error.
        zmq_assert (false);
    }
    return 0;
}

//  Create, bind and connect PGM socket.
int zmq::pgm_socket_t::init (bool udp_encapsulation_, const char *network_)
{
    //  Can not open transport before destroying old one.
    zmq_assert (sock == NULL);
    zmq_assert (options.rate > 0);

    //  Zero counter used in msgrecv.
    nbytes_rec = 0;
    nbytes_processed = 0;
    pgm_msgv_processed = 0;

    uint16_t port_number;
    struct pgm_addrinfo_t *res = NULL;
    sa_family_t sa_family;

    pgm_error_t *pgm_error = NULL;

    if (init_address (network_, &res, &port_number) < 0) {
        goto err_abort;
    }

    zmq_assert (res != NULL);

    //  RISE PGM profile: a separate unicast repair port only exists for
    //  UDP encapsulation (epgm://), and it must differ from the data port,
    //  otherwise the option would silently recreate the shared-port defect
    //  it is meant to remove.
    if (options.rise_pgm_repair_port != 0
        && (!udp_encapsulation_
            || options.rise_pgm_repair_port == (int) port_number)) {
        goto err_abort;
    }

    //  Pick up detected IP family.
    sa_family = res->ai_send_addrs[0].gsr_group.ss_family;

    //  Create IP/PGM or UDP/PGM socket.
    if (udp_encapsulation_) {
        if (!pgm_socket (&sock, sa_family, SOCK_SEQPACKET, IPPROTO_UDP,
                         &pgm_error)) {
            //  Invalid parameters don't set pgm_error_t.
            zmq_assert (pgm_error != NULL);
            if (pgm_error->domain == PGM_ERROR_DOMAIN_SOCKET
                && (pgm_error->code != PGM_ERROR_BADF
                    && pgm_error->code != PGM_ERROR_FAULT
                    && pgm_error->code != PGM_ERROR_NOPROTOOPT
                    && pgm_error->code != PGM_ERROR_FAILED))

                //  User, host, or network configuration or transient error.
                goto err_abort;

            //  Fatal OpenPGM internal error.
            zmq_assert (false);
        }

        //  All options are of data type int
        const int encapsulation_port = port_number;
        //  RISE PGM profile: optional separate unicast repair port.
        //  OpenPGM binds every PGM socket's receive socket to the multicast
        //  encapsulation port with SO_REUSEPORT, so a sender and a receiver
        //  on the same channel in one process share a kernel reuseport
        //  group and unicast NAK/SPMR datagrams are hashed between them;
        //  the recv-only socket discards them and repairs never happen.
        //  With a repair port the sender's receive socket is bound to that
        //  port alone (the data port is restored before the group options
        //  copy it) and receivers address NAK/SPMR there. All peers must
        //  agree on the value; 0 keeps the legacy single-port behaviour.
        const int repair_port = options.rise_pgm_repair_port;
        const int ucast_port = repair_port ? repair_port : encapsulation_port;
        const int bind_mcast_port =
          (!receiver && repair_port) ? repair_port : encapsulation_port;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_UDP_ENCAP_UCAST_PORT,
                             &ucast_port, sizeof (ucast_port)))
            goto err_abort;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_UDP_ENCAP_MCAST_PORT,
                             &bind_mcast_port, sizeof (bind_mcast_port)))
            goto err_abort;
    } else {
        if (!pgm_socket (&sock, sa_family, SOCK_SEQPACKET, IPPROTO_PGM,
                         &pgm_error)) {
            //  Invalid parameters don't set pgm_error_t.
            zmq_assert (pgm_error != NULL);
            if (pgm_error->domain == PGM_ERROR_DOMAIN_SOCKET
                && (pgm_error->code != PGM_ERROR_BADF
                    && pgm_error->code != PGM_ERROR_FAULT
                    && pgm_error->code != PGM_ERROR_NOPROTOOPT
                    && pgm_error->code != PGM_ERROR_FAILED))

                //  User, host, or network configuration or transient error.
                goto err_abort;

            //  Fatal OpenPGM internal error.
            zmq_assert (false);
        }
    }

    {
        const int rcvbuf = (int) options.rcvbuf;
        if (rcvbuf >= 0) {
            if (!pgm_setsockopt (sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
                                 sizeof (rcvbuf)))
                goto err_abort;
        }

        const int sndbuf = (int) options.sndbuf;
        if (sndbuf >= 0) {
            if (!pgm_setsockopt (sock, SOL_SOCKET, SO_SNDBUF, &sndbuf,
                                 sizeof (sndbuf)))
                goto err_abort;
        }

        const int max_tpdu = (int) options.multicast_maxtpdu;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_MTU, &max_tpdu,
                             sizeof (max_tpdu)))
            goto err_abort;
    }

    if (receiver) {
        //  RISE PGM profile 0: relaxed NAK schedule (legacy RISE values),
        //  tuned for single-packet messages. Profile 1 (mesh)
        //  keeps the 2 s NAK back-off: OpenPGM declares a hole lost, with
        //  no NAK, when the back-off expires before the source's address
        //  (NLA) is known, and the back-off is a uniform random draw up to
        //  this value, so a shorter one raises the loss probability for
        //  the first message from a newly seen source. Profile 1 shortens
        //  the NAK repeat and allows 20 repair attempts per sequence, each
        //  waiting 800 ms for RDATA after an NCF, so a multi-packet message
        //  can be repaired at the profile's repair rate instead of being
        //  discarded after three attempts.
        const bool mesh = options.rise_pgm_profile == 1;
        const int recv_only = 1, rxw_max_tpdu = (int) options.multicast_maxtpdu,
                  rxw_sqns = compute_sqns (rxw_max_tpdu),
                  peer_expiry = pgm_secs (300), spmr_expiry = pgm_msecs (25),
                  nak_bo_ivl = pgm_secs (2),
                  nak_rpt_ivl = mesh ? pgm_msecs (500) : pgm_secs (10),
                  nak_rdata_ivl = pgm_msecs (800),
                  nak_data_retries = mesh ? 20 : 3,
                  nak_ncf_retries = mesh ? 20 : 3;

        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_RECV_ONLY, &recv_only,
                             sizeof (recv_only))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_RXW_SQNS, &rxw_sqns,
                                sizeof (rxw_sqns))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_PEER_EXPIRY,
                                &peer_expiry, sizeof (peer_expiry))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_SPMR_EXPIRY,
                                &spmr_expiry, sizeof (spmr_expiry))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_NAK_BO_IVL, &nak_bo_ivl,
                                sizeof (nak_bo_ivl))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_NAK_RPT_IVL,
                                &nak_rpt_ivl, sizeof (nak_rpt_ivl))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_NAK_RDATA_IVL,
                                &nak_rdata_ivl, sizeof (nak_rdata_ivl))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_NAK_DATA_RETRIES,
                                &nak_data_retries, sizeof (nak_data_retries))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_NAK_NCF_RETRIES,
                                &nak_ncf_retries, sizeof (nak_ncf_retries)))
            goto err_abort;
    } else {
        const bool mesh = options.rise_pgm_profile == 1;
        const int send_only = 1, max_rte = (int) ((options.rate * 1000) / 8),
                  //  RISE PGM profile 0: cap repair (RDATA) traffic at the
                  //  legacy 1500 B/s (one packet per second) and send only
                  //  the 30 s heartbeat SPM. Profile 1 (mesh): repairs at
                  //  12500 B/s (about nine packets per second) and a short
                  //  post-send SPM schedule, so the loss of a message's
                  //  trailing packet is typically detected by one of the
                  //  post-send SPMs (+200 ms, +400 ms) or the 2 s ambient one (a
                  //  lost SPM delays it) instead of at a 30 s ambient SPM.
                  max_repair_rte = mesh ? 12500 : 1500,
                  txw_max_tpdu = (int) options.multicast_maxtpdu,
                  txw_sqns = compute_sqns (txw_max_tpdu),
                  //  Ambient SPM: profile 1 announces every 2 s on an idle
                  //  channel so a receiver that joins after this sender
                  //  learns the sender's address (NLA) before its first
                  //  message. OpenPGM declares a hole lost, without a NAK,
                  //  when the NAK back-off expires before the NLA is known
                  //  (receiver.c nak_rb_state), which can happen for holes in
                  //  the first message from a source. This shortens the
                  //  exposure; it does not remove it.
                  ambient_spm = mesh ? pgm_secs (2) : pgm_secs (30),
                  legacy_heartbeat_spm[] = {pgm_secs (30)},
                  //  Post-send schedule. OpenPGM (timer.c) uses the first
                  //  interval twice (reset, then re-added on the first fire)
                  //  and the last one only terminates the series, so this
                  //  array announces at +200 ms and +400 ms after the last
                  //  data; the ambient cadence continues afterwards. The
                  //  upstream 100 ms x4 series competes with data on
                  //  bandwidth-limited links.
                  mesh_heartbeat_spm[] = {pgm_msecs (200), pgm_secs (1),
                                          pgm_secs (30)};
        const int *heartbeat_spm = mesh ? mesh_heartbeat_spm : legacy_heartbeat_spm;
        const socklen_t heartbeat_len =
          mesh ? sizeof (mesh_heartbeat_spm) : sizeof (legacy_heartbeat_spm);

        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_SEND_ONLY, &send_only,
                             sizeof (send_only))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_ODATA_MAX_RTE, &max_rte,
                                sizeof (max_rte))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_RDATA_MAX_RTE,
                                &max_repair_rte, sizeof (max_repair_rte))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_TXW_SQNS, &txw_sqns,
                                sizeof (txw_sqns))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_AMBIENT_SPM,
                                &ambient_spm, sizeof (ambient_spm))
            || !pgm_setsockopt (sock, IPPROTO_PGM, PGM_HEARTBEAT_SPM,
                                heartbeat_spm, heartbeat_len))
            goto err_abort;
    }

    //  PGM transport GSI.
    struct pgm_sockaddr_t addr;

    memset (&addr, 0, sizeof (addr));
    addr.sa_port = port_number;
    addr.sa_addr.sport = DEFAULT_DATA_SOURCE_PORT;

    //  Create random GSI.
    uint32_t buf[2];
    buf[0] = generate_random ();
    buf[1] = generate_random ();
    if (!pgm_gsi_create_from_data (&addr.sa_addr.gsi, (uint8_t *) buf, 8))
        goto err_abort;


    //  Bind a transport to the specified network devices.
    struct pgm_interface_req_t if_req;
    memset (&if_req, 0, sizeof (if_req));
    if_req.ir_interface = res->ai_recv_addrs[0].gsr_interface;
    if_req.ir_scope_id = 0;
    if (AF_INET6 == sa_family) {
        struct sockaddr_in6 sa6;
        memcpy (&sa6, &res->ai_recv_addrs[0].gsr_group, sizeof (sa6));
        if_req.ir_scope_id = sa6.sin6_scope_id;
    }
    if (!pgm_bind3 (sock, &addr, sizeof (addr), &if_req, sizeof (if_req),
                    &if_req, sizeof (if_req), &pgm_error)) {
        //  Invalid parameters don't set pgm_error_t.
        zmq_assert (pgm_error != NULL);
        if ((pgm_error->domain == PGM_ERROR_DOMAIN_SOCKET
             || pgm_error->domain == PGM_ERROR_DOMAIN_IF)
            && (pgm_error->code != PGM_ERROR_INVAL
                && pgm_error->code != PGM_ERROR_BADF
                && pgm_error->code != PGM_ERROR_FAULT))

            //  User, host, or network configuration or transient error.
            goto err_abort;

        //  Fatal OpenPGM internal error.
        zmq_assert (false);
    }

    //  RISE PGM profile: the sender's receive socket is bound to the
    //  repair port; restore the data port before PGM_JOIN_GROUP and
    //  PGM_SEND_GROUP copy it into the group addresses.
    if (udp_encapsulation_ && !receiver && options.rise_pgm_repair_port) {
        const int data_port = port_number;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_UDP_ENCAP_MCAST_PORT,
                             &data_port, sizeof (data_port)))
            goto err_abort;
    }

    //  Join IP multicast groups.
    for (unsigned i = 0; i < res->ai_recv_addrs_len; i++) {
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_JOIN_GROUP,
                             &res->ai_recv_addrs[i], sizeof (struct group_req)))
            goto err_abort;
    }
    if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_SEND_GROUP,
                         &res->ai_send_addrs[0], sizeof (struct group_req)))
        goto err_abort;

    pgm_freeaddrinfo (res);
    res = NULL;

    //  Set IP level parameters.
    {
        //  RISE PGM profile: multicast loopback follows ZMQ_MULTICAST_LOOP
        //  (needed for several endpoints on one host) instead of always 0.
        const int multicast_loop = options.multicast_loop ? 1 : 0;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_MULTICAST_LOOP,
                             &multicast_loop, sizeof (multicast_loop)))
            goto err_abort;

        const int multicast_hops = options.multicast_hops;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_MULTICAST_HOPS,
                             &multicast_hops, sizeof (multicast_hops)))
            goto err_abort;

        //  Expedited Forwarding PHB for network elements, no ECN.
        //  Ignore return value due to varied runtime support.
        const int dscp = 0x2e << 2;
        if (AF_INET6 != sa_family)
            pgm_setsockopt (sock, IPPROTO_PGM, PGM_TOS, &dscp, sizeof (dscp));

        const int nonblocking = 1;
        if (!pgm_setsockopt (sock, IPPROTO_PGM, PGM_NOBLOCK, &nonblocking,
                             sizeof (nonblocking)))
            goto err_abort;
    }

    //  Connect PGM transport to start state machine.
    if (!pgm_connect (sock, &pgm_error)) {
        //  Invalid parameters don't set pgm_error_t.
        zmq_assert (pgm_error != NULL);
        goto err_abort;
    }

    //  For receiver transport preallocate pgm_msgv array.
    if (receiver) {
        zmq_assert (options.in_batch_size > 0);
        //  RISE PGM profile: one APDU per pgm_recvmsgv call. Upstream sizes
        //  the vector from ZMQ_IN_BATCH_SIZE (six entries at 8192 B). With
        //  more than one entry OpenPGM 5.3.128 can flush the same peer twice
        //  inside one call; if the first flush delivered data and the second
        //  meets a hole, pgm_flush_peers_pending zeroes peer->last_commit
        //  with packets still committed, pgm_rxw_remove_commit never runs
        //  again, the trail is pinned and, once the hole is declared lost,
        //  every new packet is dropped on the BOUNDS branch (only the
        //  aggregate PACKETS_DISCARDED counter moves, no NAK). One entry
        //  returns after each delivered APDU, so the next call removes the
        //  commit before reading. Cost: more pgm_recvmsgv calls per burst.
        pgm_msgv_len = 1;

        pgm_msgv = (pgm_msgv_t *) malloc (sizeof (pgm_msgv_t) * pgm_msgv_len);
        alloc_assert (pgm_msgv);
    }

#if defined ZMQ_HAVE_LINUX && defined IP_MULTICAST_ALL
    //  RISE PGM profile: only deliver datagrams of the joined group(s) to
    //  this receive socket. Linux otherwise delivers every group bound to
    //  the same port. Done after connect,
    //  when OpenPGM exposes the receive socket. Failure is fatal because
    //  zmq_has ("rise_pgm") promises group isolation.
    if (receiver) {
        int recv_fd = -1;
        socklen_t recv_fd_len = sizeof (recv_fd);
        const int mc_all = 0;
        if (!pgm_getsockopt (sock, IPPROTO_PGM, PGM_RECV_SOCK, &recv_fd,
                             &recv_fd_len)
            || recv_fd < 0
            || setsockopt (recv_fd, IPPROTO_IP, IP_MULTICAST_ALL, &mc_all,
                           sizeof (mc_all))
                 != 0)
            goto err_abort;
    }
#endif

    return 0;

err_abort:
    if (sock != NULL) {
        pgm_close (sock, FALSE);
        sock = NULL;
    }
    if (res != NULL) {
        pgm_freeaddrinfo (res);
        res = NULL;
    }
    if (pgm_error != NULL) {
        pgm_error_free (pgm_error);
        pgm_error = NULL;
    }
    errno = EINVAL;
    return -1;
}

zmq::pgm_socket_t::~pgm_socket_t ()
{
    if (pgm_msgv)
        free (pgm_msgv);
    if (sock)
        pgm_close (sock, TRUE);
}

//  Get receiver fds. receive_fd_ is signaled for incoming packets,
//  waiting_pipe_fd_ is signaled for state driven events and data.
void zmq::pgm_socket_t::get_receiver_fds (fd_t *receive_fd_,
                                          fd_t *waiting_pipe_fd_)
{
    socklen_t socklen;
    bool rc;

    zmq_assert (receive_fd_);
    zmq_assert (waiting_pipe_fd_);

    socklen = sizeof (*receive_fd_);
    rc =
      pgm_getsockopt (sock, IPPROTO_PGM, PGM_RECV_SOCK, receive_fd_, &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*receive_fd_));

    socklen = sizeof (*waiting_pipe_fd_);
    rc = pgm_getsockopt (sock, IPPROTO_PGM, PGM_PENDING_SOCK, waiting_pipe_fd_,
                         &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*waiting_pipe_fd_));
}

//  Get fds and store them into user allocated memory.
//  send_fd is for non-blocking send wire notifications.
//  receive_fd_ is for incoming back-channel protocol packets.
//  rdata_notify_fd_ is raised for waiting repair transmissions.
//  pending_notify_fd_ is for state driven events.
void zmq::pgm_socket_t::get_sender_fds (fd_t *send_fd_,
                                        fd_t *receive_fd_,
                                        fd_t *rdata_notify_fd_,
                                        fd_t *pending_notify_fd_)
{
    socklen_t socklen;
    bool rc;

    zmq_assert (send_fd_);
    zmq_assert (receive_fd_);
    zmq_assert (rdata_notify_fd_);
    zmq_assert (pending_notify_fd_);

    socklen = sizeof (*send_fd_);
    rc = pgm_getsockopt (sock, IPPROTO_PGM, PGM_SEND_SOCK, send_fd_, &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*receive_fd_));

    socklen = sizeof (*receive_fd_);
    rc =
      pgm_getsockopt (sock, IPPROTO_PGM, PGM_RECV_SOCK, receive_fd_, &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*receive_fd_));

    socklen = sizeof (*rdata_notify_fd_);
    rc = pgm_getsockopt (sock, IPPROTO_PGM, PGM_REPAIR_SOCK, rdata_notify_fd_,
                         &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*rdata_notify_fd_));

    socklen = sizeof (*pending_notify_fd_);
    rc = pgm_getsockopt (sock, IPPROTO_PGM, PGM_PENDING_SOCK,
                         pending_notify_fd_, &socklen);
    zmq_assert (rc);
    zmq_assert (socklen == sizeof (*pending_notify_fd_));
}

//  Send one APDU, transmit window owned memory.
//  data_len_ must be less than one TPDU.
size_t zmq::pgm_socket_t::send (unsigned char *data_, size_t data_len_)
{
    size_t nbytes = 0;

    const int status = pgm_send (sock, data_, data_len_, &nbytes);

    //  We have to write all data as one packet.
    if (nbytes > 0) {
        zmq_assert (status == PGM_IO_STATUS_NORMAL);
        zmq_assert (nbytes == data_len_);
    } else {
        zmq_assert (status == PGM_IO_STATUS_RATE_LIMITED
                    || status == PGM_IO_STATUS_WOULD_BLOCK);

        if (status == PGM_IO_STATUS_RATE_LIMITED)
            errno = ENOMEM;
        else
            errno = EBUSY;
    }

    //  Save return value.
    last_tx_status = status;

    return nbytes;
}

long zmq::pgm_socket_t::get_rx_timeout ()
{
    if (last_rx_status != PGM_IO_STATUS_RATE_LIMITED
        && last_rx_status != PGM_IO_STATUS_TIMER_PENDING)
        return -1;

    struct timeval tv;
    socklen_t optlen = sizeof (tv);
    const bool rc = pgm_getsockopt (sock, IPPROTO_PGM,
                                    last_rx_status == PGM_IO_STATUS_RATE_LIMITED
                                      ? PGM_RATE_REMAIN
                                      : PGM_TIME_REMAIN,
                                    &tv, &optlen);
    zmq_assert (rc);

    const long timeout = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);

    return timeout;
}

long zmq::pgm_socket_t::get_tx_timeout ()
{
    if (last_tx_status != PGM_IO_STATUS_RATE_LIMITED)
        return -1;

    struct timeval tv;
    socklen_t optlen = sizeof (tv);
    const bool rc =
      pgm_getsockopt (sock, IPPROTO_PGM, PGM_RATE_REMAIN, &tv, &optlen);
    zmq_assert (rc);

    const long timeout = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);

    return timeout;
}

//  Return max TSDU size without fragmentation from current PGM transport.
size_t zmq::pgm_socket_t::get_max_tsdu_size ()
{
    int max_tsdu = 0;
    socklen_t optlen = sizeof (max_tsdu);

    bool rc = pgm_getsockopt (sock, IPPROTO_PGM, PGM_MSS, &max_tsdu, &optlen);
    zmq_assert (rc);
    zmq_assert (optlen == sizeof (max_tsdu));
    return (size_t) max_tsdu;
}

//  pgm_recvmsgv is called to fill the pgm_msgv array up to  pgm_msgv_len.
//  In subsequent calls data from pgm_msgv structure are returned.
ssize_t zmq::pgm_socket_t::receive (void **raw_data_, const pgm_tsi_t **tsi_, uint32_t *sequence_)
{
    size_t raw_data_len = 0;

    //  We just sent all data from pgm_transport_recvmsgv up
    //  and have to return 0 that another engine in this thread is scheduled.
    if (nbytes_rec == nbytes_processed && nbytes_rec > 0) {
        //  Reset all the counters.
        nbytes_rec = 0;
        nbytes_processed = 0;
        pgm_msgv_processed = 0;
        errno = EAGAIN;
        return 0;
    }

    //  If we have are going first time or if we have processed all pgm_msgv_t
    //  structure previously read from the pgm socket.
    if (nbytes_rec == nbytes_processed) {
        //  Check program flow.
        zmq_assert (pgm_msgv_processed == 0);
        zmq_assert (nbytes_processed == 0);
        zmq_assert (nbytes_rec == 0);

        //  Receive a vector of Application Protocol Domain Unit's (APDUs)
        //  from the transport.
        pgm_error_t *pgm_error = NULL;

        const int status = pgm_recvmsgv (sock, pgm_msgv, pgm_msgv_len,
                                         MSG_ERRQUEUE, &nbytes_rec, &pgm_error);

        //  Invalid parameters.
        zmq_assert (status != PGM_IO_STATUS_ERROR);

        last_rx_status = status;

        //  In a case when no ODATA/RDATA fired POLLIN event (SPM...)
        //  pgm_recvmsg returns PGM_IO_STATUS_TIMER_PENDING.
        if (status == PGM_IO_STATUS_TIMER_PENDING) {
            zmq_assert (nbytes_rec == 0);

            //  In case if no RDATA/ODATA caused POLLIN 0 is
            //  returned.
            nbytes_rec = 0;
            errno = EBUSY;
            return 0;
        }

        //  Send SPMR, NAK, ACK is rate limited.
        if (status == PGM_IO_STATUS_RATE_LIMITED) {
            zmq_assert (nbytes_rec == 0);

            //  In case if no RDATA/ODATA caused POLLIN 0 is returned.
            nbytes_rec = 0;
            errno = ENOMEM;
            return 0;
        }

        //  No peers and hence no incoming packets.
        if (status == PGM_IO_STATUS_WOULD_BLOCK) {
            zmq_assert (nbytes_rec == 0);

            //  In case if no RDATA/ODATA caused POLLIN 0 is returned.
            nbytes_rec = 0;
            errno = EAGAIN;
            return 0;
        }

        //  Data loss.
        if (status == PGM_IO_STATUS_RESET) {
            struct pgm_sk_buff_t *skb = pgm_msgv[0].msgv_skb[0];

            //  Save lost data TSI. RISE fix: copy it, because the skb is
            //  freed below and upstream returned a pointer into it. A
            //  receiver reading the freed TSI could look up the wrong
            //  peer, leave the real peer's decoder joined across the gap
            //  and then parse payload bytes as frame headers.
            reset_tsi = skb->tsi;
            *tsi_ = &reset_tsi;
            nbytes_rec = 0;

            //  In case of dala loss -1 is returned.
            errno = EINVAL;
            pgm_free_skb (skb);
            return -1;
        }

        zmq_assert (status == PGM_IO_STATUS_NORMAL);
    } else {
        zmq_assert (pgm_msgv_processed <= pgm_msgv_len);
    }

    // Zero byte payloads are valid in PGM, but not 0MQ protocol.
    zmq_assert (nbytes_rec > 0);

    // Only one APDU per pgm_msgv_t structure is allowed.
    zmq_assert (pgm_msgv[pgm_msgv_processed].msgv_len == 1);

    struct pgm_sk_buff_t *skb = pgm_msgv[pgm_msgv_processed].msgv_skb[0];

    //  Take pointers from pgm_msgv_t structure.
    *sequence_ = skb->sequence;
    *raw_data_ = skb->data;
    raw_data_len = skb->len;

    //  Save current TSI.
    *tsi_ = &skb->tsi;

    //  Move the the next pgm_msgv_t structure.
    pgm_msgv_processed++;
    zmq_assert (pgm_msgv_processed <= pgm_msgv_len);
    nbytes_processed += raw_data_len;

    return raw_data_len;
}

void zmq::pgm_socket_t::process_upstream ()
{
    pgm_msgv_t dummy_msg;

    size_t dummy_bytes = 0;
    pgm_error_t *pgm_error = NULL;

    const int status = pgm_recvmsgv (sock, &dummy_msg, 1, MSG_ERRQUEUE,
                                     &dummy_bytes, &pgm_error);

    //  Invalid parameters.
    zmq_assert (status != PGM_IO_STATUS_ERROR);

    //  No data should be returned.
    zmq_assert (dummy_bytes == 0
                && (status == PGM_IO_STATUS_TIMER_PENDING
                    || status == PGM_IO_STATUS_RATE_LIMITED
                    || status == PGM_IO_STATUS_WOULD_BLOCK));

    last_rx_status = status;

    if (status == PGM_IO_STATUS_TIMER_PENDING)
        errno = EBUSY;
    else if (status == PGM_IO_STATUS_RATE_LIMITED)
        errno = ENOMEM;
    else
        errno = EAGAIN;
}

int zmq::pgm_socket_t::compute_sqns (int tpdu_)
{
    //  Convert rate into B/ms.
    uint64_t rate = uint64_t (options.rate) / 8;

    //  Compute the size of the buffer in bytes.
    uint64_t size = uint64_t (options.recovery_ivl) * rate;

    //  Translate the size into number of packets.
    uint64_t sqns = size / tpdu_;

    //  Buffer should be able to hold at least one packet.
    if (sqns == 0)
        sqns = 1;

    return (int) sqns;
}

#endif
