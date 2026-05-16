#include <stdio.h>
#include <string.h>

#ifdef WITH_NCURSES
#  include <curses.h>
#else
#  include <termios.h>
#  include <unistd.h>
#  include <sys/select.h>
#endif

#include "ntop.h"
#include "tui.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"

static const char *view_labels[VIEW_COUNT] = {
    "[1] Interfaces",
    "[2] Connections",
    "[3] WiFi",
    "[4] Packets",
};

void tui_bar(double val, double max, int width, char *out) {
    int filled = (max > 0.0) ? (int)((val / max) * width) : 0;
    if (filled > width) filled = width;
    for (int i = 0; i < width; i++)
        out[i] = (i < filled) ? '#' : '.';
    out[width] = '\0';
}

static void dispatch_view(const ntop_state_t *s) {
    switch (s->active_view) {
    case VIEW_IFACE:   view_iface_draw(s);   break;
    case VIEW_CONNS:   view_conns_draw(s);   break;
    case VIEW_WIFI:    view_wifi_draw(s);    break;
    case VIEW_PACKETS: view_packets_draw(s); break;
    default: break;
    }
}

/* ═══════════════════════════════════════════════════════════
   ncurses implementation
   ═══════════════════════════════════════════════════════════ */
#ifdef WITH_NCURSES

void tui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN,  -1);
        init_pair(2, COLOR_CYAN,   -1);
        init_pair(3, COLOR_YELLOW, -1);
        init_pair(4, COLOR_RED,    -1);
    }
}

void tui_cleanup(void) {
    endwin();
}

static void draw_tabbar(const ntop_state_t *s) {
    attron(A_BOLD);
    printw(" ntop v" NTOP_VERSION);
    attroff(A_BOLD);
    printw("  ");
    for (int i = 0; i < VIEW_COUNT; i++) {
        if (i == (int)s->active_view)
            attron(A_REVERSE | A_BOLD);
        printw(" %s ", view_labels[i]);
        if (i == (int)s->active_view)
            attroff(A_REVERSE | A_BOLD);
        printw(" ");
    }
    printw(" [Tab] cycle  [q]uit");
}

void tui_draw(const ntop_state_t *s) {
    erase();
    move(0, 0);
    draw_tabbar(s);
    move(1, 0);
    hline(ACS_HLINE, getmaxx(stdscr));
    move(2, 0);
    dispatch_view(s);
    refresh();
}

int tui_poll_key(int timeout_ms) {
    timeout(timeout_ms);
    int ch = getch();
    if (ch == ERR)      return 0;
    if (ch == KEY_UP)   return NTOP_KEY_UP;
    if (ch == KEY_DOWN) return NTOP_KEY_DOWN;
    return ch;
}

/* ═══════════════════════════════════════════════════════════
   ANSI fallback (embedded / no-ncurses)
   ═══════════════════════════════════════════════════════════ */
#else

static struct termios g_saved_term;

void tui_init(void) {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &g_saved_term);
    raw = g_saved_term;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

void tui_cleanup(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term);
    printf("\033[0m\n");
}

static void draw_tabbar(const ntop_state_t *s) {
    printf("\033[1m ntop v" NTOP_VERSION "\033[0m  ");
    for (int i = 0; i < VIEW_COUNT; i++) {
        if (i == (int)s->active_view)
            printf("\033[7m %s \033[0m", view_labels[i]);
        else
            printf(" %s ", view_labels[i]);
        printf(" ");
    }
    printf(" [Tab] cycle  [q]uit\n");
    printf("------------------------------------------------------------\n");
}

void tui_draw(const ntop_state_t *s) {
    printf("\033[2J\033[H");
    draw_tabbar(s);
    dispatch_view(s);
    fflush(stdout);
}

static int read_char_timeout(int us) {
    fd_set fds;
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = us;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
        unsigned char c = 0;
        if (read(STDIN_FILENO, &c, 1) == 1)
            return (int)c;
    }
    return -1;
}

int tui_poll_key(int timeout_ms) {
    fd_set fds;
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;

    unsigned char c = 0;
    if (read(STDIN_FILENO, &c, 1) != 1)
        return 0;

    if (c != '\033')
        return (int)c;

    /* ESC — try to read an ANSI escape sequence within 10 ms */
    int b = read_char_timeout(10000);
    if (b != '[')
        return '\033';   /* bare ESC or unrecognised sequence */

    int d = read_char_timeout(10000);
    if (d == 'A') return NTOP_KEY_UP;
    if (d == 'B') return NTOP_KEY_DOWN;
    return '\033';
}

#endif /* WITH_NCURSES */
