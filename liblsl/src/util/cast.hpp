// Original liblsl code: Copyright (C) 2012 Christian A. Kothe, MIT License
// Modifications: Copyright (C) 2025-2026 The Regents of the University of California.
// All Rights Reserved. Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#pragma once
#include <string>

namespace lsl {
template <typename T> std::string to_string(T val) { return std::to_string(val); }
template <> std::string to_string(double val);
template <> std::string to_string(float val);

template <typename T> T from_string(const std::string &str);
template <> inline bool from_string(const std::string &str) { return str == "1" || str == "true"; }

} // namespace lsl
