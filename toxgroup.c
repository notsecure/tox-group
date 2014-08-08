#define TARGET_CONN 5 //number of connections wanted
#define MAX_CONN 8 //cant be above 8 -> see code to increase
#define CONN_ID(g, c) (c - g->connlist)

#define SIZE_PEER_INFO 8

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
    uint16_t port;
    uint8_t timeout, info;
} AUDIO;

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t timeout, info;

    uint8_t connect, peer_request, nsend_audio;
    uint8_t padding[5];

    struct {
        uint32_t ip;
        uint16_t port;
    } send_audio[4];
} CONN;

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t timeout, info;

    uint8_t conn_id, attempted, failed;
    _Bool pinged;
    uint8_t padding[4];
} PEER;

enum {
    INFO_HAVEAUDIO = 1,
    INFO_WANTCONN = 2,
    INFO_MAXCONN = 4,
};

enum {
    /* protocol */
    PACKET_ACCEPT,
    PACKET_REJECT,
    PACKET_CONNECT,
    PACKET_KILL,

    PACKET_PEER_REQ,
    PACKET_PEERS,

    PACKET_ALIVE,
    PACKET_ALIVE_REQ,

    PACKET_CONFIRM,

    PACKET_REQUEST_AUDIO,
    PACKET_STOP_AUDIO,

    /* reliable */
    PACKET_CHAT,

    /* unreliable */
    PACKET_AUDIO,
    PACKET_AUDIO_INDIRECT,
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
    uint8_t info, audio_sequence, timer;

    /* */
    PEER *peerlist;
    AUDIO *audiolist;
    int npeer, nconn, naudio;

    /* recent packets */
    PACKET *packet;

    /* connection list */
    CONN connlist[MAX_CONN];
};

static void packet_sendall(ToxGroup *g, PACKET *pk);
static void conn_send(ToxGroup *g, CONN *c, const uint8_t *data, uint16_t length);
static PEER* peer_add(ToxGroup *g, uint32_t ip, uint16_t port, uint8_t timeout, uint8_t info);

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

static AUDIO* audio_find(ToxGroup *g, uint32_t ip, uint16_t port)
{
    int i;
    AUDIO *a;

    if(!g->naudio) {
        return NULL;
    }

    i = 0;
    do {
        a = &g->audiolist[i];
        if(a->ip == ip && a->port == port) {
            return a;
        }

        i++;
    } while(i != g->naudio);

    return NULL;
}

static AUDIO* audio_add(ToxGroup *g, uint32_t ip, uint16_t port, _Bool indirect)
{
    AUDIO *a;
    if(!(a = audio_find(g, ip, port))) {
        a = realloc(g->audiolist, (g->naudio + 1) * sizeof(AUDIO));
        if(!a) {
            return NULL;
        }
        g->audiolist = a;
        a += g->naudio++;

        a->ip = ip;
        a->port = port;
        a->timeout = 0;
        a->info = indirect;
        return a;
    }

    a->timeout = 0;
    a->info = indirect;
    return a;
}

static void audio_recv(ToxGroup *g, CONN *c, const uint8_t *data, uint16_t len, _Bool indirect)
{
    CONN *cc;
    int i, j;
    uint32_t ip;
    uint16_t port;

    /* todo: dont do this, avoid copying memory around */
    uint8_t packet[len + 7];
    if(indirect) {
        memcpy(&ip, data + 1, 4);
        memcpy(&port, data + 5, 2);
        audio_add(g, ip, port, 1);
        memcpy(packet, data, len);
    } else {
        audio_add(g, c->ip, c->port, 0);
        packet[0] = PACKET_AUDIO_INDIRECT;
        memcpy(packet + 1, &c->ip, 6);
        memcpy(packet + 7, data + 1, len - 1);
        len += 6;
    }

    debug("recv audio %u\n", packet[7]);

    i = 0;
    do {
        cc = &g->connlist[i];
        if(!cc->ip) {
            continue;
        }

        if(cc == c) {
            continue;
        }

        j = 0;
        do {
            if(cc->send_audio[j].ip == c->ip && cc->send_audio[j].port == c->port) {
                _send(g, cc->ip, cc->port, packet, len);
            }
        } while(++j != 4);
    } while(++i != MAX_CONN);
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
    *d++ = g->info;
    i = 0;
    do {
        p = &g->peerlist[i];
        /* exlude the peer we are sending to */
        if(p->ip != c->ip || p->port != c->port) {
            memcpy(d, p, SIZE_PEER_INFO); d += SIZE_PEER_INFO;
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
    *d++ = g->info;
    i = 0;
    do {
        cc = &g->connlist[i];
        if(!cc->ip) {
            continue;
        }

        /* exlude the peer we are sending to */
        if(cc->ip != c->ip || cc->port != c->port) {
            memcpy(d, cc, SIZE_PEER_INFO); d += SIZE_PEER_INFO;
        }
    } while(++i != MAX_CONN);
    conn_send(g, c, data, d - data);
}

static void conn_remove(ToxGroup *g, CONN *c)
{
    g->nconn--;
    c->ip = 0;
    c->connect = 0;

    g->info &= ~INFO_MAXCONN;
    if(g->nconn < TARGET_CONN) {
        g->info |= INFO_WANTCONN;
    }
}

static void conn_recv(ToxGroup *g, CONN *c, uint8_t *data, int len)
{
    /* todo, missing some length checks on some packets */
    PEER *p;
    uint32_t ip;
    uint16_t port;

    c->timeout = 0;

    if(!len) {
        return;
    }

    switch(data[0]) {
    case PACKET_KILL: {
        debug("connection killed\n");
        conn_remove(g, c);
        break;
    }

    case PACKET_REJECT:
        debug("connection rejected\n");
        conn_remove(g, c);
        /* fall through */
    case PACKET_ACCEPT:
        if(c->connect) {
            debug("connection accepted\n");
            c->connect = 0;
        }
        /* fall through */
    case PACKET_ALIVE: {
        data++;
        c->info = *data++;
        len -= 2;
        do {
            len -= SIZE_PEER_INFO;
            if(len < 0) {
                break;
            }
            memcpy(&ip, data, 4);
            memcpy(&port, data + 4, 2);
            p = peer_add(g, ip, port, data[6], data[7]);
            if(p && (data[7] & INFO_HAVEAUDIO) && !conn_find(g, ip, port) && !audio_find(g, ip, port)) {
                audio_add(g, ip, port, 1);//repeats audio_find
                data--;
                data[0] = PACKET_REQUEST_AUDIO;
                conn_send(g, c, data, 7);
            }
            data += SIZE_PEER_INFO;
        } while(1);

        c->peer_request = 0;
        break;
    }

    case PACKET_CONNECT: {
        conn_sendpeers(g, c, data);
        break;
    }

    case PACKET_ALIVE_REQ: {
        conn_sendalive(g, c, data);
        break;

    }

    case PACKET_CHAT: {
        if(packet_add(g, c, PACKET_CHAT, data, len - 1)) {
            g->message_callback(g, data + 6, len - 6);
        }
        break;
    }

    case PACKET_CONFIRM: {
        packet_confirm(g, c, data + 1, len - 1);
        break;
    }

    case PACKET_REQUEST_AUDIO: {
        memcpy(&c->send_audio[c->nsend_audio], data + 1, 6);
        c->nsend_audio = (c->nsend_audio + 1) & 3;
        break;
    }

    case PACKET_STOP_AUDIO: {
        break;
    }

    case PACKET_AUDIO_INDIRECT:
    case PACKET_AUDIO: {
        audio_recv(g, c, data, len, (data[0] != PACKET_AUDIO));
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
    if(g->nconn >= TARGET_CONN) {
        g->info &= ~INFO_WANTCONN;
    }

    if(g->nconn == MAX_CONN) {
        g->info |= INFO_MAXCONN;
    }

    c->ip = p->ip;
    c->port = p->port;
    c->timeout = 0;
    c->info = request ? 0 : INFO_WANTCONN;
    c->connect = request;
    c->peer_request = 0;
    c->nsend_audio = 0;

    memset(&c->send_audio, 0, sizeof(c->send_audio));

    p->pinged = 1;
    p->attempted++;

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

static PEER* peer_add(ToxGroup *g, uint32_t ip, uint16_t port, uint8_t timeout, uint8_t info)
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
        p->timeout = timeout;
        p->info = info;
        p->pinged = 0;
        p->conn_id = 0xFF;
        p->attempted = 0;
        return p;
    }

    if(timeout < p->timeout) {
        p->timeout = timeout;
    }
    p->info = info;
    return p;
}

static CONN* peer_add_connection(ToxGroup *g, uint32_t ip, uint16_t port, _Bool request)
{
    CONN *c;
    PEER *p;

    p = peer_add(g, ip, port, 0, 0);
    c = conn_new(g, p, request);

    return c;
}

static void peer_send(ToxGroup *g, PEER *p, const uint8_t *data, uint16_t length)
{
    _send(g, p->ip, p->port, data, length);
}

static PEER* peer_choose(ToxGroup *g)
{
    PEER *p, *rp;
    int i;
    uint8_t attempted;

    rp = NULL;
    attempted = 0xFF;
    i = 0;
    do {
        p = &g->peerlist[i];
        if(p->attempted < attempted && (p->info & INFO_WANTCONN) && !conn_find(g, p->ip, p->port)) {
            attempted = p->attempted;
            rp = p;
        }
        i++;
    } while(i != g->npeer);

    return rp;
}

static ToxGroup* _toxgroup_new(void)
{
    ToxGroup *g;
    u_long mode;

    if(!(g = calloc(sizeof(ToxGroup), 1))) {
        return NULL;
    }

    g->then = get_time() - msec(1000);
    g->info = INFO_WANTCONN;

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

static void _toxgroup_senddata(ToxGroup *g, uint8_t type, const uint8_t *data, uint16_t len)
{
    PACKET *pk;
    uint32_t id;

    if(len > 128) {
        return;
    }

    id = (uint32_t)get_time();
    if((pk = packet_new(g, type, 0, id, data, len))) {
        packet_sendall(g, pk);
    }
}

void toxgroup_sendchat(ToxGroup *g, const uint8_t *chat, uint16_t len)
{
    _toxgroup_senddata(g, PACKET_CHAT, chat, len);
}

static void _toxgroup_sendall(ToxGroup *g, const uint8_t *data, uint16_t len)
{
    CONN *c;
    int i;

    i = 0;
    do {
        c = &g->connlist[i];
        if(!c->ip) {
            continue;
        }
        conn_send(g, c, data, len);
    } while(++i != MAX_CONN);
}

void toxgroup_beginaudio(ToxGroup *g)
{
    g->info |= INFO_HAVEAUDIO;
}

void toxgroup_sendaudio(ToxGroup *g)
{
    uint8_t packet[2];
    packet[0] = PACKET_AUDIO;
    packet[1] = g->audio_sequence++;
    _toxgroup_sendall(g, packet, 2);
}

void toxgroup_endaudio(ToxGroup *g)
{
    g->info &= ~INFO_HAVEAUDIO;
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
    AUDIO *a;
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
            peer_add(g, addr.ip, addr.port, 0, 0);
            continue;
        }

        if(!len) {
            continue;
        }

        /* join packet only valid packet */
        if(data[0] != PACKET_CONNECT) {
            data[0] = PACKET_KILL;
            _send(g, addr.ip, addr.port, data, 1);
            continue;
        }

        if(g->nconn == MAX_CONN) {
            peer_add(g, addr.ip, addr.port, 0, 0);

            d = data;
            *d++ = PACKET_REJECT;
            *d++ = g->info;
            i = 0;
            do {
                c = &g->connlist[i];
                if(c->ip != addr.ip || c->port != addr.port) {
                    memcpy(d, c, SIZE_PEER_INFO); d += SIZE_PEER_INFO;
                }
            } while(++i != MAX_CONN);
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

        g->timer++;
        if(g->timer == 5) {
            if(g->nconn > TARGET_CONN) {
                /* find a peer who doesn't want connections and kill the connection */
                i = 0;
                do {
                    c = &g->connlist[i];
                    if(!c->ip) {
                        continue;
                    }

                    if(!(c->info & INFO_WANTCONN)) {
                        conn_remove(g, c);
                        break;
                    }
                } while(++i != MAX_CONN);
            }
            g->timer = 0;
        }

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
            continue;
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

            if(p->timeout == 20 && g->nconn != MAX_CONN && !conn_find(g, p->ip, p->port)) {
                /* peer is timing out, attempt to connect to check if alive (prevent splits) */
                conn_new(g, p, 1);
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
            continue;
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

        if(!g->naudio) {
            continue;
        }

        i = 0;
        do {
            a = &g->audiolist[i];
            a->timeout++;

            if(a->timeout == 5) {
                debug("audio req timeout\n");
                g->naudio--;
                memmove(a, a + 1, (g->naudio - i) * sizeof(AUDIO));
                /* dont need to remove from connection because connection will always time out first
                 todo: deal will case where do() hasn't been called for a long time
                 */
                continue;
            }
            i++;
        } while(i != g->naudio);
    } while(1);
}
