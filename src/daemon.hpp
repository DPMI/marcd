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

#ifndef MA_DAEMON_H
#define MA_DAEMON_H

#include <pthread.h>
#include <vector>

class Daemon {
public:
  virtual ~Daemon(){}

  virtual int init(){ return 0; };
  virtual int cleanup(){ return 0; };
  virtual int run() = 0;

  /**
   * Create a instance of a daemon.
   * @param timeout How long to wait for initialization to finish.
   * @param barrier Blocks on barrier before calling run().
   */
  template <class T>
  static int instantiate(unsigned int timeout, pthread_barrier_t* barrier){
    T* daemon = new T;
    return instantiate_real(daemon, timeout, barrier);
  }

  static void join_all();
  static void interupt_all();

  /**
   * Wake up thread from any pending select, poll, etc operations where it is
   * waiting for file descriptors to be ready. Won't work if the thread is
   * blocked in any other operation.
   */
  void interupt();

 protected:
  /**
   * This file descriptor should be watched in all calls to select, poll, etc
   * and if the thread is interupted this FD will be readable.
   *
   * This is refered to as the self-pipe trick.
   */
  int interupt_fd() const { return pipe[0]; }

private:
  static int instantiate_real(Daemon* daemon, unsigned int timeout, pthread_barrier_t* barrier);
  static void* entry(void* data);

  void join();

  pthread_t thread;
  int pipe[2];

  static std::vector<Daemon*> daemons;
};

#endif /* MA_DAEMON_H */
