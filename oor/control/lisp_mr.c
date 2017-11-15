/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "lisp_mr.h"
#include "../lib/sockets.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"
#include "../liblisp/lisp_messages.h"

static oor_ctrl_dev_t *mr_ctrl_alloc();
static int mr_ctrl_construct(oor_ctrl_dev_t *dev);
static void mr_ctrl_destruct(oor_ctrl_dev_t *dev);
static void mr_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void mr_ctrl_run(oor_ctrl_dev_t *dev);
static int mr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc);
int mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state);
int mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status);
int mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
fwd_info_t *mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
fwd_info_t *mr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
static inline lisp_mr_t * lisp_mr_cast(oor_ctrl_dev_t *dev);
static int mr_recv_map_request(lisp_mr_t *mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
int process_blockchain_api_msg(struct sock *sl);

/* implementation of ctrl base functions */
ctrl_dev_class_t mr_ctrl_class = {
        .alloc = mr_ctrl_alloc,
        .construct = mr_ctrl_construct,
        .dealloc = mr_ctrl_dealloc,
        .destruct = mr_ctrl_destruct,
        .run = mr_ctrl_run,
        .recv_msg = mr_recv_msg,
        .if_link_update = mr_if_link_update,
        .if_addr_update = mr_if_addr_update,
        .route_update = mr_route_update,
        .get_fwd_entry = mr_get_forwarding_entry
};


static oor_ctrl_dev_t *
mr_ctrl_alloc()
{
    lisp_mr_t *mr;
    mr = xzalloc(sizeof(lisp_mr_t));
    return(&mr->super);
}

static int
mr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_mr_t * mr = lisp_mr_cast(dev);
    lisp_addr_t src_addr;
    int rx_port = 16001;

    lisp_addr_ippref_from_char("127.0.0.1",&src_addr);
    mr->blockchain_api_socket = open_udp_datagram_socket(AF_INET);
    bind_socket(mr->blockchain_api_socket, AF_INET, &src_addr, rx_port);

    //TODO function called when received message from
    sockmstr_register_read_listener(smaster, process_blockchain_api_msg, NULL,mr->blockchain_api_socket);

    return(GOOD);
}

//TODO To process replys of blckchain process
int
process_blockchain_api_msg(struct sock *sl)
{
    OOR_LOG(LDBG_1,"Received message from blockchain api");
    return (GOOD);
}

static void
mr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    OOR_LOG(LDBG_1,"Map Resolver device destroyed");
}

static void
mr_ctrl_dealloc(oor_ctrl_dev_t *dev) {
    lisp_mr_t *mr = lisp_mr_cast(dev);
    free(mr);
    OOR_LOG(LDBG_1, "Freed Map Resolver ...");
}

static void
mr_ctrl_run(oor_ctrl_dev_t *dev)
{
    OOR_LOG(LDBG_1, "\nStarting OOR as a Map Resolver ...\n");


}


static int
mr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = 0;
    lisp_msg_type_e type;
    lisp_mr_t *mr = lisp_mr_cast(dev);
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;
    packet_tuple_t inner_tuple;
    uint16_t src_port;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {

        if (lisp_msg_ecm_decap(msg, &src_port) != GOOD) {
            return (BAD);
        }
        type = lisp_msg_type(msg);
        pkt_parse_inner_5_tuple(msg, &inner_tuple);
        uconn_init(&aux_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
        ext_uc = uc;
        int_uc = &aux_uc;
        ecm_hdr = lbuf_lisp_hdr(msg);
    }else{
        int_uc = uc;
    }

    switch (type) {
    case LISP_MAP_REQUEST:
        if (!ecm_hdr){
            OOR_LOG(LDBG_1, "MR: Received a not Encap Map Request. Discarding!");
            ret = BAD;
            break;
        }
        ret = mr_recv_map_request(mr, msg, ecm_hdr, int_uc, ext_uc);
        ret = GOOD;
        break;
    case LISP_MAP_REPLY:
    case LISP_MAP_REGISTER:
    case LISP_MAP_NOTIFY:
    case LISP_INFO_NAT:
    default:
        OOR_LOG(LDBG_3, "Map-Resolver: Received control message with type %d."
                " Discarding!", type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        OOR_LOG(LDBG_1,"MR: Failed to process LISP control message");
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "MR: Completed processing of LISP control message");
        return (ret);
    }
}

int
mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state)
{
    return (GOOD);
}
int
mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    return (GOOD);
}
int
mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return (GOOD);
}

fwd_info_t *
mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

fwd_info_t *
mr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

static inline lisp_mr_t *
lisp_mr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &mr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_mr_t, super));
}

/*************************** PROCESS MESSAGES ********************************/

static int
mr_recv_map_request(lisp_mr_t *mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lisp_addr_t *seid = NULL;
    lisp_addr_t *deid = NULL;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr = NULL;
    lbuf_t  b;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }


    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        OOR_LOG(LDBG_1, "MR can not receive Map Request Probe. Discarding!");
        goto err;
    }

    if (MREQ_SMR(mreq_hdr)) {
        OOR_LOG(LDBG_1, "MR can not receive SMR Map Request. Discarding!");
        goto err;
    }

    if (MREQ_REC_COUNT(mreq_hdr) > 1){
        OOR_LOG(LDBG_1, "This version of MR only supports messages with one record. Discarding!");
        goto err;
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    /* Process records and build Map-Reply */

    if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
        goto err;
    }
    OOR_LOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));


    // TODO : Send message to the Blockchain API requesting this EID. Don't forget to
    // use the nonce -> MREQ_NONCE(mreq_hdr)





    /* Check the existence of the requested EID */
    // TODO: Example of how the mrep is created. This message should be created if
    // blockchain return a mapping instead of a set of MSs
//    mrep = lisp_msg_create(LISP_MAP_REPLY);
//    if (!map_loc_e) {
//        OOR_LOG(LDBG_1,"EID %s not locally configured!",
//                lisp_addr_to_char(deid));
//        goto err;
//    }
//    map = map_local_entry_mapping(map_loc_e);
//    lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
//            ? &int_uc->la: NULL);
//
//    mrep_hdr = lisp_msg_hdr(mrep);
//    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
//    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);
//
//    /* SEND MAP-REPLY */
//    if (map_reply_fill_uconn(&xtr->tr, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
//        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
//        goto err;
//    }
//    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
//    send_msg(&xtr->super, mrep, &send_uc);

done:
    glist_destroy(itr_rlocs);
    //lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    //lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(BAD);
}

