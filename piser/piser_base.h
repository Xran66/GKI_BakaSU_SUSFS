// android-base 字符串工具的最小实现（只覆盖 AOSP 序列化器用到的部分）
#pragma once
#include <string>
#include <vector>

namespace android {
namespace base {

inline std::vector<std::string> Split(const std::string& s, const std::string& delim) {
  std::vector<std::string> out;
  size_t start = 0;
  while (true) {
    size_t p = s.find(delim, start);
    if (p == std::string::npos) {
      out.emplace_back(s.substr(start));
      break;
    }
    out.emplace_back(s.substr(start, p - start));
    start = p + delim.size();
  }
  return out;
}

inline std::string Join(const std::vector<std::string>& v, const std::string& delim) {
  std::string out;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i) out += delim;
    out += v[i];
  }
  return out;
}

inline bool StartsWith(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

inline std::string Trim(const std::string& s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

}  // namespace base
}  // namespace properties
