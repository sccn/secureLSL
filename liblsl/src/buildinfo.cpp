// Original liblsl code: Copyright (C) 2012 Christian A. Kothe, MIT License
// Modifications: Copyright (C) 2025-2026 The Regents of the University of California.
// All Rights Reserved. Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifdef LSL_SECURITY_ENABLED
#include "lsl_security.h"
#endif

extern "C" {
#include "../include/lsl/common.h"

LIBLSL_C_API const char *lsl_library_info(void) {
#ifdef LSL_LIBRARY_INFO_STR
	return LSL_LIBRARY_INFO_STR;
#else
	return "Unknown (not set by build system)";
#endif
}

LIBLSL_C_API const char *lsl_base_version(void) {
#ifdef LSL_BASE_VERSION
	return LSL_BASE_VERSION;
#else
	return "unknown";
#endif
}

LIBLSL_C_API const char *lsl_security_version(void) {
#ifdef LSL_SECURITY_VERSION_STR
	return LSL_SECURITY_VERSION_STR;
#else
	return "0.0.0";
#endif
}

LIBLSL_C_API const char *lsl_full_version(void) {
#ifdef LSL_FULL_VERSION_STR
	return LSL_FULL_VERSION_STR;
#else
#ifdef LSL_BASE_VERSION
	return LSL_BASE_VERSION;
#else
	return "unknown";
#endif
#endif
}

LIBLSL_C_API int32_t lsl_is_secure_build(void) {
#ifdef LSL_IS_SECURE_BUILD
	return LSL_IS_SECURE_BUILD;
#else
	return 0;
#endif
}

LIBLSL_C_API int32_t lsl_local_security_enabled(void) {
#ifdef LSL_SECURITY_ENABLED
	return lsl::security::LSLSecurity::instance().is_enabled() ? 1 : 0;
#else
	return 0;
#endif
}

LIBLSL_C_API int32_t lsl_security_is_locked(void) {
#ifdef LSL_SECURITY_ENABLED
	return lsl::security::LSLSecurity::instance().is_locked() ? 1 : 0;
#else
	return 0;
#endif
}

LIBLSL_C_API int32_t lsl_security_unlock(const char *passphrase) {
#ifdef LSL_SECURITY_ENABLED
	if (!passphrase) return 0;
	auto result = lsl::security::LSLSecurity::instance().unlock(passphrase);
	return result == lsl::security::SecurityResult::SUCCESS ? 1 : 0;
#else
	(void)passphrase;
	return 0;
#endif
}

LIBLSL_C_API const char *lsl_local_security_fingerprint(void) {
#ifdef LSL_SECURITY_ENABLED
	auto& sec = lsl::security::LSLSecurity::instance();
	if (!sec.is_enabled()) return "";
	static std::string fingerprint;
	fingerprint = lsl::security::LSLSecurity::compute_fingerprint(sec.get_public_key());
	return fingerprint.c_str();
#else
	return "";
#endif
}
}
