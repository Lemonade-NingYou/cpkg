#ifndef OUTERROR_H
#define OUTERROR_H

typedef enum ErrorInfo {
    Successful = 0,

	// build
    ReadConfigFile = 1,
    ChangeDir,
    CreateCpkgDir,
    CreateConfigJsonFile,
    CreateLibsDir,
    LibNotExist,
    CreateIncludeDir,
    IncludeNotExist,
    GzipConfigFile,
    MemoryAllocError,
    HashComputeError,
    GzipPocketFile,
    ParseConfigFormat,
    CreateEndFile,

	// install
    OpenCPLFile,
    ReadHashError,
    InvalidMagicError,
    ReadJsonSizeError,
    ReadJsonMemoryError,
    ReadPocketSizeError,
    ReadPocketMemoryError,
    HashMismatchError,
    DecompressJsonError,
    WriteTempConfigError,
    ParseConfigError,
    DecompressPocketError,
    InstallLibsError,
    InstallIncludeError,
    CreateManifestError,
    CreateTempDirError,
} ErrorInfo;

void ErrorArg(int errorCode);

#endif // OUTERROR_H