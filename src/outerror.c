#include "../include/outerror.h"
#include <stdio.h>
#include <stdlib.h>

void ErrorArg(int errorCode) {
	switch (errorCode) {
		case ReadConfigFile:
			fprintf(stderr, "Error: Failed to read configuration file.\n");
			break;
		case ChangeDir:
			fprintf(stderr, "Error: Unable to change directory.\n");
			break;
		case CreateCpkgDir:
			fprintf(stderr, "Error: .cpkg directory not found.\n");
			break;
		case CreateConfigJsonFile:
			fprintf(stderr, "Error: Unable to create configuration JSON file.\n");
			break;
		case CreateLibsDir:
			fprintf(stderr, "Error: libs directory not found.\n");
			break;
		case LibNotExist:
			fprintf(stderr, "Error: Library file does not exist.\n");
			break;
		case CreateIncludeDir:
			fprintf(stderr, "Error: include directory not found.\n");
			break;
		case IncludeNotExist:
			fprintf(stderr, "Error: Header file does not exist.\n");
			break;
		case GzipConfigFile:
			fprintf(stderr, "Error: Unable to compress configuration file.\n");
			break;
		case GzipPocketFile:
			fprintf(stderr, "Error: Unable to compress libs and include directories.\n");
			break;
		case ParseConfigFormat:
			fprintf(stderr, "Error: Unable to parse configuration file format.\n");
			break;
		case CreateEndFile:
			fprintf(stderr, "Error: Unable to create final output file.\n");
			break;
        case OpenCPLFile:
            fprintf(stderr, "Error: Unable to open CPL file.\n");
            break;
        case ReadHashError:
            fprintf(stderr, "Error: Failed to read hash from package.\n");
            break;
        case InvalidMagicError:
            fprintf(stderr, "Error: Invalid magic number (not a valid CPL package).\n");
            break;
        case ReadJsonSizeError:
            fprintf(stderr, "Error: Failed to read JSON size.\n");
            break;
        case ReadJsonMemoryError:
            fprintf(stderr, "Error: Failed to read JSON compressed data.\n");
            break;
        case ReadPocketSizeError:
            fprintf(stderr, "Error: Failed to read pocket size.\n");
            break;
        case ReadPocketMemoryError:
            fprintf(stderr, "Error: Failed to read pocket compressed data.\n");
            break;
        case HashMismatchError:
            fprintf(stderr, "Error: Package data hash mismatch (corrupted or tampered).\n");
            break;
        case DecompressJsonError:
            fprintf(stderr, "Error: Failed to decompress config.json.\n");
            break;
        case WriteTempConfigError:
            fprintf(stderr, "Error: Failed to write temporary config file.\n");
            break;
        case ParseConfigError:
            fprintf(stderr, "Error: Failed to parse config.json (invalid JSON).\n");
            break;
        case DecompressPocketError:
            fprintf(stderr, "Error: Failed to decompress pocket data.\n");
            break;
        case InstallLibsError:
            fprintf(stderr, "Error: Failed to install library files.\n");
            break;
        case InstallIncludeError:
            fprintf(stderr, "Error: Failed to install header files.\n");
            break;
        case CreateManifestError:
            fprintf(stderr, "Error: Failed to create installation manifest.\n");
            break;
        case CreateTempDirError:
            fprintf(stderr, "Error: Failed to create temporary directory.\n");
            break;
		default:
			fprintf(stderr, "Unknown error code: %d\n", errorCode);
	}
}