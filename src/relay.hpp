/**
* Measurement Area Control Daemon
* Copyright (C) 2003-2013 (see AUTHORS)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifndef MA_RELAY_H
#define MA_RELAY_H

#include "daemon.hpp"

class Relay: public Daemon {
public:
  Relay();

  virtual int init();
  virtual int cleanup();
  virtual int run();

private:
	/* wrapper with error logging */
	bool setsockopt(int level, const char* name, int optname, void* optval, socklen_t optlen);
  int sd;
};

#endif /* MARCD_RELAY_H */
