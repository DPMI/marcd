#ifndef MARCD_CONFIGFILE_H
#define MARCD_CONFIGFILE_H

namespace config {

	/**
	 * Tell which configuration file was used or NULL if not used.
	 */
	const char* filename();

	int load(int argc, char* argv[]);

};

#endif /* MARCD_CONFIGFILE_H */
