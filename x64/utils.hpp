#pragma once
#include "storage.hpp"
#include "auth_guard.hpp"

inline bool CheckIfJsonKeyExists(const std::string& path, const std::string& section)
{
    std::ifstream file(path);
    if (!file.good()) return false;
    const auto data = json::parse(file, nullptr, false);
    return data.is_object() && data.contains(section);
}
