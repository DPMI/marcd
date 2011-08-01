#ifndef MA_RELAY_H
#define MA_RELAY_H

#include "daemon.h"

class Relay: public Daemon {
public:
  Relay();

  virtual int init();
  virtual int cleanup();
  virtual int run();

 private:
  int sd;
};

#endif /* MARCD_RELAY_H */
