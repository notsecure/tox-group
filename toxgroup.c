/* todo: handle REJECT packet, scalability */

#define TARGET_CONN 4
#define MAX_CONN 8 //cant be above 8 -> see code to increase
#define CONN_ID(g, c) (c - g->connlist)

#define SIZE_IP_PORT 6

static void* write_ip_port(uint8_t *dest, uint32_t ip, uint16_t port)
{
    memcpy(dest, &ip, 4);
    memcpy(dest + 4, &port, 2);
    return dest + 6;
}

static void* read_ip_port(uint8_t *src, uint32_t *ip, uint16_t *port)
{
    memcpy(ip, src, 4);
    memcpy(port, src + 4, 2);
    return src + 6;
}

typedef struct PACKET PACKET;

struct PACKET {
    PACKET *next;
    uint16_t length;
    uint8_t confirmed; //1 bit per max conn

    uint8_t packet;
    uint32_t id; //unique id
    uint8_t timeout;
    uint8_t data[0];
};

typedef struct {
    uint32_t ip;
    uint16_t port, timeout;
    uint8_t connect, peer_request;
    uint8_t padding[6];
} CONN;

typedef struct {
    uint32_t ip;
    uint16_t port, timeout;
    uint16_t conn_id, attempted;
    _Bool pinged;
    uint8_t padding[3];
} PEER;

enum {
    PACKET_ACCEPT,
    PACKET_REJECT,
    PACKET_CONNECT,
    PACKET_PEER_REQ,
    PACKET_PEERS,

    PACKET_ALIVE,
    PACKET_ALIVE_REQ,

    PACKET_CHAT,
    PACKET_CONFIRM,
};

typedef struct ToxGroup ToxGroup;

struct ToxGroup {
    /* user set variables */
    void *userdata;
    void (*peer_callback)(ToxGroup *g, uint8_t id, uint8_t change);
    void (*message_callback)(ToxGroup *g, const uint8_t *msg, uint16_t length);

    /* */
    uint32_t sock;

    /* time variables */
    uint64_t now, then;

    /* */
    PEER *peerlist;
    int npeer, nconn;

    /* recent packets */
    PACKET *packet;

    /* connection list */
    CONN connlist[MAX_CONN];
};

static void packet_sendall(ToxGroup *g, PACKET *pk);
static void conn_send(ToxGroup *g, CONN *c, const uint8_t *data, uint16_t length);
static PEER* peer_add(ToxGroup *g, uint32_t ip, uint16_t port);

static void _send(ToxGroup *g, uint32_t ip, uint16_t port, const uint8_t *data, uint16_t length)
{
    struct {
        uint16_t family, port;
        uint32_t ip;
        uint8_t padding[8];
    } addr = {
        .family = AF_INET,
        .port = port,
        .ip = ip
    };

    if(sendto(g->sock, data, length, 0, (struct sockaddr*)&addr, sizeof(addr)) != length) {
        debug("sendto failed\n");
    }
}

static PACKET* packet_find(ToxGroup *g, uint32_t id)
{
    PACKET *pk;

    if(!(pk = g->packet)) {
        return NULL;
    }

    do {
        if(id == pk->id) {
            return pk;
        };
    } while((pk = pk->next));

    return NULL;
}

static PACKET* packet_new(ToxGroup *g, uint8_t p, uint8_t timeout, uint32_t id, const uint8_t *data, uint16_t len)
{
    PACKET *pk, **out, *next;

    out = &g->packet;
    next = NULL;

    if((pk = g->packet)) {
        next = pk;
        do {
            if(pk->id == id) {
                return pk;
            }

            if(timeout <= pk->timeout) {
                out = &pk->next;
                next = pk->next;
            }
        } while((pk = pk->next));
    }

    pk = malloc(sizeof(PACKET) + len);
    if(!pk) {
        return NULL;
    }

    pk->next = next;
    pk->length = len;
    pk->confirmed = 0;

    pk->packet = p;
    pk->id = id;
    pk->timeout = timeout;
    memcpy(pk->data, data, len);

    *out = pk;
    return pk;
}

static _Bool packet_add(ToxGroup *g, CONN *c, uint8_t packet, uint8_t *data, uint16_t len)
{
    PACKET *pk;
    uint32_t id;
    _Bool ret;

    if(len < sizeof(id) + 1) {
        return 0;
    }

    memcpy(&id, data + 1, sizeof(id));

    data[0] = PACKET_CONFIRM;
    conn_send(g, c, data, 5);

    if((pk = packet_new(g, packet, data[5], id, data + 6, len - 5))) {
        ret = (pk->confirmed == 0);
        pk->confirmed |= (1 << CONN_ID(g, c));
        packet_sendall(g, pk);
        return ret;
    }

    return 0;
}

static void packet_confirm(ToxGroup *g, CONN *c, uint8_t *data, uint16_t len)
{
    PACKET *pk;
    uint32_t id;

    if(len < sizeof(id)) {
        return;
    }

    memcpy(&id, data, sizeof(id));

    if(!(pk = packet_find(g, id))) {
        return;
    }

    pk->confirmed |= (1 << CONN_ID(g, c));
}

static void packet_sendall(ToxGroup *g, PACKET *pk)
{
    CONN *c;
    int i;

    i = 0;
    do {
        c = &g->connlist[i];
        if(!c->ip || c->connect || (pk->confirmed & (1 << i))) {
            continue;
        }
        conn_send(g, c, &pk->packet, pk->length + 6);
    } while(++i != MAX_CONN);
}

static CONN* conn_find(ToxGroup *g, uint32_t ip, uint16_t port)
{
    CONN *c;
    int i;

    if(!g->nconn) {
        return NULL;
    }

    i = 0;
    do {
        c = &g->connlist[i];
        if(c->ip == ip && c->port == port) {
            return c;
        }
    } while(++i != MAX_CONN);

    return NULL;
}

static void conn_send(ToxGroup *g, CONN *c, const uint8_t *data, uint16_t length)
{
    _send(g, c->ip, c->port, data, length);
}

static void conn_sendall(ToxGroup *g, CONN *c, int confirmed_bit)
{
    PACKET *pk;
    if(!(pk = g->packet)) {
        return;
    }

    do {
        if(pk->confirmed & confirmed_bit) {
            continue;
        }

        conn_send(g, c, &pk->packet, pk->length + 6);
    } while((pk = pk->next));
}

static void conn_sendpeers(ToxGroup *g, CONN *c, uint8_t *data)
{
    PEER *p;
    int i;
    uint8_t *d;

    d = data;
    *d++ = PACKET_ACCEPT;
    i = 0;
    do {
        p = &g->peerlist[i];
        /* exlude the peer we are sending to */
        if(p->ip != c->ip || p->port != c->port) {
            d = write_ip_port(d, p->ip, p->port);
        }
        i++;
    } while(i != g->npeer);
    conn_send(g, c, data, d - data);
}

static void conn_sendalive(ToxGroup *g, CONN *c, uint8_t *data)
{
    CONN *cc;
    int i;
    uint8_t *d;

    d = data;
    *d++ = PACKET_ALIVE;
    i = 0;
    do {
        cc = &g->connlist[i];
        if(!cc->ip) {
            continue;
        }

        /* exlude the peer we are sending to */
        if(cc->ip != c->ip || cc->port != c->port) {
            d = write_ip_port(d, cc->ip, cc->port);
        }
    } while(++i != MAX_CONN);
    conn_send(g, c, data, d - data);
}

static void conn_recv(ToxGroup *g, CONN *c, uint8_t *data, int len)
{
    uint32_t ip;
    uint16_t port;

    c->timeout = 0;

    if(!len) {
        return;
    }

    len--;

    switch(data[0]) {
    case PACKET_ACCEPT: {
        data++;
        do {
            len -= SIZE_IP_PORT;
            if(len < 0) {
                break;
            }
            data = read_ip_port(data, &ip, &port);
            peer_add(g, ip, port);
        } while(1);

        if(c->connect) {
            debug("connection accepted\n");
        }

        c->connect = 0;
        break;
    }

    case PACKET_CONNECT: {
        conn_sendpeers(g, c, data);
        break;
    }

    case PACKET_ALIVE: {
        data++;
        do {
            len -= SIZE_IP_PORT;
            if(len < 0) {
                break;
            }
            data = read_ip_port(data, &ip, &port);
            peer_add(g, ip, port);
        } while(1);

        c->peer_request = 0;
        break;
    }

    case PACKET_ALIVE_REQ: {
        conn_sendalive(g, c, data);
        break;

    }

    case PACKET_CHAT: {
        if(packet_add(g, c, PACKET_CHAT, data, len)) {
            g->message_callback(g, data + 6, len - 5);
        }
        break;
    }

    case PACKET_CONFIRM: {
        packet_confirm(g, c, data + 1, len);
        break;
    }
    }
}

static CONN* conn_new(ToxGroup *g, PEER *p, _Bool request)
{
    CONN *c;
    PACKET *pk;
    int i;

    i = -1;
    do {
        c = &g->connlist[++i];
    } while(c->ip);

    p->conn_id = i;
    g->nconn++;

    c->ip = p->ip;
    c->port = p->port;
    c->timeout = 0;
    c->connect = request;
    c->peer_request = 0;

    p->pinged = 1;
    p->attempted = 1;

    if(!(pk = g->packet)) {
        return c;
    }

    do {
        pk->confirmed |= (1 << i);
    } while((pk = pk->next));

    return c;
}

static PEER* peer_find(ToxGroup *g, uint32_t ip, uint16_t port)
{
    int i;
    PEER *p;

    if(!g->npeer) {
        return NULL;
    }

    i = 0;
    do {
        p = &g->peerlist[i];
        if(p->ip == ip && p->port == port) {
            return p;
        }

        i++;
    } while(i != g->npeer);

    return NULL;
}

static PEER* peer_add(ToxGroup *g, uint32_t ip, uint16_t port)
{
    PEER *p;
    if(!(p = peer_find(g, ip, port))) {
        p = realloc(g->peerlist, (g->npeer + 1) * sizeof(PEER));
        if(!p) {
            return NULL;
        }
        g->peerlist = p;
        p += g->npeer++;

        p->ip = ip;
        p->port = port;
        p->timeout = 0;
        p->pinged = 0;
        p->conn_id = 0xFFFF;
        p->attempted = 0;
        return p;
    }

    p->timeout = 0;
    return p;
}

static CONN* peer_add_connection(ToxGroup *g, uint32_t ip, uint16_t port, _Bool request)
{
    CONN *c;
    PEER *p;

    p = peer_add(g, ip, port);
    c = conn_new(g, p, request);

    return c;
}

static void peer_send(ToxGroup *g, PEER *p, const uint8_t *data, uint16_t length)
{
    _send(g, p->ip, p->port, data, length);
}

static PEER* peer_choose(ToxGroup *g)
{
    PEER *p;
    int i;

    i = 0;
    do {
        p = &g->peerlist[i];
        if(!p->attempted) {
            return p;
        }
        i++;
    } while(i != g->npeer);

    return NULL;
}

static ToxGroup* _toxgroup_new(void)
{
    ToxGroup *g;
    u_long mode;

    if(!(g = calloc(sizeof(ToxGroup), 1))) {
        return NULL;
    }

    g->then = get_time() - msec(1000);

    if((g->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == ~0) {
        free(g);
        return NULL;
    }

    /* set nonblocking */
    mode = 1;
    if(ioctl(g->sock, FIONBIO, &mode) == -1) {
        close(g->sock);
        free(g);
        return NULL;
    }

    return g;
}

ToxGroup* toxgroup_new(void)
{
    ToxGroup *g;

    if(!(g = _toxgroup_new())) {
        return NULL;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = DEFAULT_PORT
    };

    if((bind(g->sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)) {
        close(g->sock);
        free(g);
        return NULL;
    }

    return g;
}

ToxGroup* toxgroup_new_bootstrap(uint32_t ip, uint16_t port)
{
    ToxGroup *g;
    if(!(g = _toxgroup_new())) {
        return NULL;
    }

    peer_add_connection(g, ip, port, 1);
    return g;
}

void toxgroup_sendchat(ToxGroup *g, const uint8_t *chat, uint16_t len)
{
    PACKET *pk;
    uint32_t id;

    if(len > 128) {
        return;
    }

    id = (uint32_t)get_time();
    if((pk = packet_new(g, PACKET_CHAT, 0, id, chat, len))) {
        packet_sendall(g, pk);
    }
}

void toxgroup_do(ToxGroup *g)
{
    struct {
        uint16_t family, port;
        uint32_t ip;
        uint8_t padding[8];
    } addr;
    socklen_t sizeofaddr;
    int len;
    uint8_t data[65536], *d;
    PEER *p;
    CONN *c;
    PACKET *pk;
    int i;
    _Bool ping;

    g->now = get_time();

    do {
        sizeofaddr = sizeof(addr);
        len = recvfrom(g->sock, data, sizeof(data), 0, (struct sockaddr*)&addr, &sizeofaddr);
        if(len < 0) {
            /* nothing left to receive */
            break;
        }

        g->peer_callback(g, 0, 0);

        /* find address in connection list */
        if((c = conn_find(g, addr.ip, addr.port)) != NULL) {
            conn_recv(g, c, data, len);
            peer_add(g, addr.ip, addr.port);
            continue;
        }

        /* invalid length packet from non-connected peer */
        if(len != 1) {
            continue;
        }

        /* join packet only valid packet */
        if(data[0] != PACKET_CONNECT) {
            continue;
        }

        if(g->nconn == MAX_CONN) {
            d = data;
            *d++ = PACKET_REJECT;
            i = 0;
            do {
                p = &g->peerlist[i];
                /* exlude the peer we are sending to */
                if(p->ip != addr.ip || p->port != addr.port) {
                    d = write_ip_port(d, p->ip, p->port);
                }
                i++;
            } while(i != g->npeer);
            _send(g, addr.ip, addr.port, data, d - data);
            continue;
        }

        /* add peer to peer list */
        if((c = peer_add_connection(g, addr.ip, addr.port, 0)) == NULL) {
            break;
        }

        /* send peerlist to peer */
        conn_sendpeers(g, c, data);
    } while(1);

    do {
        if(g->now - g->then < msec(1000)) {
            break;
        }
        g->then += msec(1000);

        g->peer_callback(g, 0, 0);

        do {
            pk = g->packet;
            if(!pk) {
                break;
            }

            pk->timeout++;
            if(pk->timeout < 30) {
                break;
            }

            g->packet = pk->next;
            free(pk);
        } while(1);

        /* peerlist */
        if(!g->npeer) {
            break;
        }

        i = 0;
        ping = 0;
        do {
            p = &g->peerlist[i];
            p->timeout++;
            if(p->timeout == 30) {
                debug("peer timeout\n");
                g->npeer--;
                memmove(p, p + 1, (g->npeer - i) * sizeof(PEER));
                /* dont need to remove from connection because connection will always time out first
                 todo: deal will case where do() hasn't been called for a long time
                 */
                continue;
            }

            /* send an empty packet to every peer once, one peer every second (for hole punching) */
            if(!ping && !p->pinged) {
                ping = p->pinged = 1;
                peer_send(g, p, NULL, 0);
            }

            i++;
        } while(i != g->npeer);

        if(g->nconn < TARGET_CONN) {
            p = peer_choose(g);
            if(p) {
                conn_new(g, p, 1);
            }
        }

        /* connections */
        if(!g->nconn) {
            break;
        }

        i = 0;
        do {
            c = &g->connlist[i];
            if(!c->ip) {
                continue;
            }

            c->timeout++;
            if(c->timeout == 20) {
                debug("conn timeout\n");
                c->ip = 0;
                g->nconn--;
                continue;
            }

            if(c->connect) {
                data[0] = PACKET_CONNECT;
                conn_send(g, c, data, 1);
                continue;
            }

            conn_sendall(g, c, 1 << i);

            if(c->peer_request == 5) {
                data[0] = PACKET_ALIVE_REQ;
                conn_send(g, c, data, 1);
                continue;
            }
            c->peer_request++;
        } while(++i != MAX_CONN);
    } while(1);
}
