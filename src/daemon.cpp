#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "daemon.hpp"
#include "log.hpp"
#include <caputils/log.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

std::vector<Daemon*> Daemon::daemons;

struct sync {
	Daemon* daemon;
	int value;
	sem_t semaphore;
	pthread_barrier_t* barrier;
};

int Daemon::instantiate_real(Daemon* daemon, unsigned int timeout, pthread_barrier_t* barrier){
	int ret;
	struct sync* td = (struct sync*)malloc(sizeof(struct sync)); /* free'd by thread entry */
	td->daemon = daemon;
	td->value = 0;
	sem_init(&td->semaphore, 0, 0); /* free'd by thread entry */
	td->barrier = barrier;

	timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec  += timeout / 1000;
	ts.tv_nsec += (timeout % 1000) * 1000000;
	if ( ts.tv_nsec > 1000000000 ){
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}

	if ( (ret=pthread_create(&daemon->thread, NULL, entry, td)) != 0 ) {
		Log::fatal("main", "pthread_create() returned %d: %s\n", ret, strerror(ret));
		return ret;
	}

	/* wait for thread initialization */
	if ( sem_timedwait(&td->semaphore, &ts) != 0 ){
		int saved = errno;
		switch ( saved ){
		case ETIMEDOUT:
			if ( pthread_kill(daemon->thread, 0) == ESRCH ){
				Log::fatal("main", "sem_timedwait(): child thread died before completing initialization\n");
			} else {
				Log::fatal("main", "sem_timedwait(): timed out waiting for initialization to finish, but child is still alive\n");
			}
			/* fallthrough */

		case EINTR:
			break;

		default:
			Log::fatal("main", "sem_timedwait() returned %d: %s\n", saved, strerror(saved));
		}
		return saved;
	}

	daemons.push_back(daemon);

	/* finished */
	return td->value;
}

void* Daemon::entry(void* data){
	struct sync* td = (struct sync*)data;
	Daemon* daemon = td->daemon;

	/* setup self-pipe */
	if ( pipe2(daemon->pipe, O_NONBLOCK) != 0 ){
		int saved = errno;
		Log::fatal("main", "pipe2() returned %d: %s\n", saved, strerror(saved));
		td->value = saved;
		sem_post(&td->semaphore);
		return NULL;
	}

	td->value = daemon->init();
	sem_post(&td->semaphore);

	if ( td->value != 0 ){
		return NULL;
	}

	if ( td->barrier ){
		pthread_barrier_wait(td->barrier);
	}

	daemon->run();
	daemon->cleanup();

	/* close pipe */
	close(daemon->pipe[0]);
	close(daemon->pipe[1]);

	/* free resources */
	sem_destroy(&td->semaphore);
	free(td);

	return 0;
}

void Daemon::join_all(){
	for ( std::vector<Daemon*>::iterator it = daemons.begin(); it != daemons.end(); ++it ){
		(*it)->join();
	}
}

void Daemon::interupt_all(){
	for ( std::vector<Daemon*>::iterator it = daemons.begin(); it != daemons.end(); ++it ){
		(*it)->interupt();
	}
}

void Daemon::join(){
	pthread_join(thread, NULL);
}

void Daemon::interupt(){
	static const char ch = 0;
	if ( write(pipe[1], &ch, 1) < 0 ){
		abort();
	}
}
