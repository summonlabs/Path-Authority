// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#if defined(PATH_AUTHORITY_SHARED)
#if defined(_WIN32) || defined(_WIN64)
#if defined(path_authority_EXPORTS)
#define PATH_AUTHORITY_API __declspec(dllexport)
#else
#define PATH_AUTHORITY_API __declspec(dllimport)
#endif
#else
#define PATH_AUTHORITY_API __attribute__((visibility("default")))
#endif
#else
#define PATH_AUTHORITY_API
#endif
