/* very basic client to test tox-group */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ncurses.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#define debug(...) wprintw(win, __VA_ARGS__); wrefresh(win);
#define countof(x) (sizeof(x)/sizeof(*(x)))

#define DEFAULT_PORT 0x707

#define msec(x) ((uint64_t)x * 1000 * 1000)

WINDOW *win, *win_info, *win_input;

uint64_t get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

    return ((uint64_t)ts.tv_sec * (1000 * 1000 * 1000)) + (uint64_t)ts.tv_nsec;
}

#include "toxgroup.c"

void update_info(ToxGroup *g)
{
    wmove(win_info, 0, 0);
    werase(win_info);

    wprintw(win_info, "npeer: %u | nconn %u | info %u\n", g->npeer, g->nconn, g->info);
    int i = 0;
    while(i < 4) {
        if(i < g->npeer) {
            PEER *p = &g->peerlist[i];
            CONN *c;
            c = conn_find(g, p->ip, p->port);
            char ip[16];
            inet_ntop(AF_INET, &p->ip, ip, 16);
            if(!c) {
                wprintw(win_info, "%s:%u (%u) (%X)\n", ip, p->port, p->timeout, p->info);
            } else {
                wprintw(win_info, "%s:%u (%u) (%u) (%u) (%X, %X)\n",
                        ip, p->port, p->timeout, c->timeout, c->connect, p->info, c->info);
            }

        } else {
            wprintw(win_info, "\n");
        }
        i++;
    }

    wrefresh(win_info);
}

_Bool send_audio;

void do_input(ToxGroup *g)
{
    static char inputstr[256] = {0};
    static int inputlen = 0;

    int ch;
    while((ch = wgetch(win_input)) != ERR) {
        switch(ch) {
            case 127: {
                if(inputlen != 0) {inputlen--;}
                break;
            }

            case '\n': {
                if(!memcmp("special", inputstr, 7)) {
                    toxgroup_beginaudio(g);
                    send_audio = 1;
                    break;
                }

                toxgroup_sendchat(g, (uint8_t*)inputstr, inputlen);
                debug("Sent: %.*s\n", inputlen, inputstr);
                //group_write_message(inputstr, inputlen);
                inputlen = 0;
                break;
            }

            default: {
                inputstr[inputlen++] = ch;
                break;
            }
        }
    }

    wmove(win_input, 0, 0);
    werase(win_input);
    wprintw(win_input, "say: %.*s", inputlen, inputstr);

    wrefresh(win_input);
}

void curses_init(void)
{
    initscr();

    noecho();
    cbreak();

    int h, w;
    getmaxyx(stdscr, h, w);

    win = newwin(h - 6, w, 5, 0);
    win_info = newwin(5, w, 0, 0);
    win_input = newwin(1, w, h - 1, 0);

    scrollok(win, TRUE);
    nodelay(win_input, TRUE);
}

_Bool info_change;

void peer_callback(ToxGroup *g, uint8_t id, uint8_t change)
{
    info_change = 1;
}

void message_callback(ToxGroup *g, const uint8_t *msg, uint16_t length)
{
    debug("Anon: %.*s\n", length, msg);
}

int main(int argc, char** argv)
{
    ToxGroup *g;

    if(argc != 1 && argc != 3) {
        printf("Usage: %s [ip port]\n", argv[0]);
        return 1;
    }

    curses_init();

    if(argc == 3) {
        uint32_t ip;
        uint16_t port;

        inet_pton(AF_INET, argv[1], &ip);
        port = strtol(argv[2], NULL, 0);

        g = toxgroup_new_bootstrap(ip, port);
    } else {
        g = toxgroup_new();
    }

    update_info(g);
    g->peer_callback = peer_callback;
    g->message_callback = message_callback;

    int z = 0;
    while(1) {
        toxgroup_do(g);

        do_input(g);
        if(info_change) {
            update_info(g);
            info_change = 0;
        }
        usleep(500);
        z++;
        if(z == 2000) {
            if(send_audio) {toxgroup_sendaudio(g);}
            z = 0;
        }
    }

    return 0;
}
