#ifndef MARCD_CONFIGFILE_H
#define MARCD_CONFIGFILE_H

namespace config {

	/**
	 * Tell which configuration file was used or NULL if not used.
	 */
	const char* filename();

	int load(int argc, char* argv[]);

	void set_control_ip(const char* addr);

};

#endif /* MARCD_CONFIGFILE_H */
