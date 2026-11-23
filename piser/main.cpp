// 从「假表」生成 bionic 可解析的 property_info（键 → exported_default_prop）。
// 用法: piser <spoof_props.txt 或 contexts.txt> <输出文件>
// 输入行: key=value（假表）或 key context [exact]（contexts 格式）
#include <fstream>
#include <iostream>
#include <vector>

#include <property_info_serializer/property_info_serializer.h>

static const char kCatchAll[] = "u:object_r:exported_default_prop:s0";

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: piser <props/contexts file> <out>\n";
    return 1;
  }
  std::ifstream in(argv[1]);
  if (!in) {
    std::cerr << "open " << argv[1] << " failed\n";
    return 1;
  }
  std::vector<android::properties::PropertyInfoEntry> entries;
  std::string line;
  int n = 0;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq != std::string::npos && line.find(' ') == std::string::npos) {
      // key=value（假表）→ 该键指向兜底 context
      std::string key = line.substr(0, eq);
      if (key.empty()) continue;
      entries.emplace_back(key, kCatchAll, "", /*exact_match=*/true);
      ++n;
      continue;
    }
    // contexts 格式: key context [exact|prefix]
    std::string key, ctx, op;
    {
      size_t p = 0;
      while (p < line.size() && line[p] == ' ') ++p;
      size_t e = line.find(' ', p);
      if (e == std::string::npos) continue;
      key = line.substr(p, e - p);
      p = e;
      while (p < line.size() && line[p] == ' ') ++p;
      e = line.find(' ', p);
      ctx = (e == std::string::npos) ? line.substr(p) : line.substr(p, e - p);
      if (ctx.empty()) continue;
      op = (e == std::string::npos) ? "" : line.substr(e + 1);
      bool exact = (op == "exact");
      entries.emplace_back(key, ctx, "", exact);
      ++n;
    }
  }
  if (entries.empty()) {
    std::cerr << "no entries\n";
    return 1;
  }
  std::string out_data, err;
  if (!android::properties::BuildTrie(entries, kCatchAll, "\\s*", &out_data, &err)) {
    std::cerr << "BuildTrie: " << err << "\n";
    return 1;
  }
  std::ofstream of(argv[2], std::ios::binary);
  of.write(out_data.data(), out_data.size());
  std::cout << "entries=" << n << " bytes=" << out_data.size() << "\n";
  return 0;
}
