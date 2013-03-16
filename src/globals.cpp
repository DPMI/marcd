#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "globals.hpp"

struct listen control = {MA_CONTROL_DEFAULT_PORT, {INADDR_ANY}, 0};
struct listen relay = {MA_RELAY_DEFAULT_PORT, {INADDR_ANY}, 0};
