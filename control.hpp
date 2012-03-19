#ifndef MARCD_CONTROL_H
#define MARCD_CONTROL_H

#include "daemon.hpp"

class Control: public Daemon {
  public:
	virtual int init();
	virtual int cleanup();
	virtual int run();
};

#endif /* MARCD_CONTROL_H */
