// 从「假表」生成 bionic 可解析的 property_info（键 → exported_default_prop）。
// 用法: piser <spoof_props.txt 或 contexts.txt> <输出文件>
// 输入行: key=value（假表）或 key context [exact]（contexts 格式）
#include <fstream>
#include <iostream>
#include <vector>

#include <property_info_serializer/property_info_serializer.h>

static const char kCatchAll[] = "u:object_r:exported_default_prop:s0";


// ---------- bionic prop_area 写入器（512KB context 区，键名 trie） ----------
// 布局: prop_area 头 128B (bytes_used/serial/magic=0x504f5250/version=0xfc6ed0ab/
// reserved[28]) + data_。trie 节点: namelen+prop+left+right+children+name。
// prop_info: serial(4)=len<<24 + value[92] + name[]（共 96+namelen+1，4 对齐）。
// 插入算法与 bionic prop_area.cpp find_property 一致（按 '.' 分段走 children BST）。

static const uint32_t PA_MAGIC = 0x504f5250u;
static const uint32_t PA_VERSION = 0xfc6ed0abu;
static const size_t PA_FILE_SIZE = 524288;   // 与真 context 区一致
static const size_t PA_HEADER = 128;

struct PaNode {
    uint32_t namelen = 0;
    uint32_t prop = 0;
    uint32_t left = 0;
    uint32_t right = 0;
    uint32_t children = 0;
    std::string name;
};

static uint32_t pa_alloc(std::vector<char>& data, uint32_t& bytes_used, size_t size) {
    uint32_t aligned = (uint32_t)((size + 3) & ~3u);
    if (bytes_used + aligned > data.size()) return 0;
    uint32_t off = bytes_used;
    bytes_used += aligned;
    return off;
}

static uint32_t pa_new_node(std::vector<char>& data, uint32_t& bytes_used,
                            const std::string& name) {
    uint32_t off = pa_alloc(data, bytes_used, 20 + name.size() + 1);
    if (off == 0) return 0;
    char* p = data.data() + off;
    uint32_t nl = (uint32_t)name.size();
    memcpy(p, &nl, 4);
    // prop/left/right/children 保持 0（root 由零填充保证，子节点也先零）
    memcpy(p + 20, name.data(), name.size());
    p[20 + name.size()] = '\0';
    return off;
}

static uint32_t pa_new_prop_info(std::vector<char>& data, uint32_t& bytes_used,
                                 const std::string& name, const std::string& value) {
    uint32_t off = pa_alloc(data, bytes_used, 96 + name.size() + 1);
    if (off == 0) return 0;
    char* p = data.data() + off;
    uint32_t serial = ((uint32_t)value.size()) << 24;
    memcpy(p, &serial, 4);
    memcpy(p + 4, value.data(), value.size());
    p[4 + value.size()] = '\0';
    memcpy(p + 96, name.data(), name.size());
    p[96 + name.size()] = '\0';
    return off;
}

// 在 children BST 里找/建 segment 节点（cmp: 长度优先，再 strncmp —— 同 bionic）
static uint32_t pa_find_or_create_child(std::vector<char>& data, uint32_t& bytes_used,
                                        uint32_t parent_off, const std::string& seg) {
    // 读 parent 的 children 头
    uint32_t child_head;
    memcpy(&child_head, data.data() + parent_off + 16, 4);
    if (child_head == 0) {
        uint32_t n = pa_new_node(data, bytes_used, seg);
        if (n == 0) return 0;
        memcpy(data.data() + parent_off + 16, &n, 4);
        return n;
    }
    uint32_t cur = child_head;
    while (true) {
        char* cp = data.data() + cur;
        uint32_t nl;
        memcpy(&nl, cp, 4);
        std::string cur_name(cp + 20, nl);
        int ret;
        if (seg.size() < nl) ret = -1;
        else if (seg.size() > nl) ret = 1;
        else ret = seg.compare(cur_name);
        if (ret == 0) return cur;
        uint32_t* next_off_p;
        if (ret < 0) next_off_p = (uint32_t*)(cp + 8);   /* left @ 8 */
        else next_off_p = (uint32_t*)(cp + 12);          /* right @ 12 */
        uint32_t next;
        memcpy(&next, next_off_p, 4);
        if (next == 0) {
            uint32_t n = pa_new_node(data, bytes_used, seg);
            if (n == 0) return 0;
            memcpy(next_off_p, &n, 4);
            return n;
        }
        cur = next;
    }
}

static int pa_write(const std::vector<std::pair<std::string, std::string>>& props,
                    const std::string& out_path) {
    std::vector<char> buf(PA_FILE_SIZE - PA_HEADER, 0);   /* data 区（不含 128B 头） */
    uint32_t bytes_used = 20;   // root node (namelen=0) 占 data[0..19]
    // 键按 '.' 分段插入
    for (auto& kv : props) {
        uint32_t cur = 0;   // root
        size_t pos = 0;
        while (true) {
            size_t sep = kv.first.find('.', pos);
            std::string seg = (sep == std::string::npos)
                ? kv.first.substr(pos) : kv.first.substr(pos, sep - pos);
            if (seg.empty()) return 2;
            cur = pa_find_or_create_child(buf, bytes_used, cur, seg);
            if (cur == 0) return 3;   // 区满
            if (sep == std::string::npos) break;
            pos = sep + 1;
        }
        uint32_t info_off = pa_new_prop_info(buf, bytes_used, kv.first, kv.second);
        if (info_off == 0) return 4;
        memcpy(buf.data() + cur + 4, &info_off, 4);
    }
    // 头部
    char hdr[PA_HEADER];
    memset(hdr, 0, sizeof(hdr));
    uint32_t bu = bytes_used;
    uint32_t zero = 0;
    memcpy(hdr + 0, &bu, 4);          // bytes_used
    memcpy(hdr + 4, &zero, 4);        // serial
    memcpy(hdr + 8, &PA_MAGIC, 4);
    memcpy(hdr + 12, &PA_VERSION, 4);
    // reserved[28] = 零
    std::ofstream of(out_path, std::ios::binary);
    of.write(hdr, PA_HEADER);
    of.write(buf.data(), buf.size());
    of.close();
    std::cout << "parea props=" << props.size() << " bytes_used=" << bytes_used << "\n";
    return 0;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: piser <props/contexts file> <out>\n";
    return 1;
  }
  if (argc >= 4 && std::string(argv[1]) == "parea") {
    // parea <props k=v> <out>
    std::ifstream pf(argv[2]);
    if (!pf) { std::cerr << "open " << argv[2] << " failed\n"; return 1; }
    std::vector<std::pair<std::string, std::string>> props;
    std::string ln;
    while (std::getline(pf, ln)) {
        if (ln.empty() || ln[0] == '#') continue;
        auto eq = ln.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        props.emplace_back(ln.substr(0, eq), ln.substr(eq + 1));
    }
    if (props.empty()) { std::cerr << "no props\n"; return 1; }
    return pa_write(props, argv[3]);
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
