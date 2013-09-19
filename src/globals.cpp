#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "globals.hpp"

struct listen control = {MA_CONTROL_DEFAULT_PORT, {INADDR_ANY}, 0};
struct listen relay = {MA_RELAY_DEFAULT_PORT, {INADDR_ANY}, 0};

int verbose_flag = 0;
int debug_flag = 0;
bool syslog_flag = false;
char* rrdpath = 0;
const char* pidfile = DATA_DIR"/marc.pid";
bool drop_priv_flag = true;
const char* drop_username = "marc";
const char* drop_group = "marc";
uid_t drop_uid = 0;
gid_t drop_gid = 0;
bool have_control_daemon = false;
bool have_relay_daemon = false;
