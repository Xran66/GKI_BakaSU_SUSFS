#pragma once
// 上游是 MSVC 工程，很多标准头（cstdint/cstring/algorithm…）靠传递包含。
// g++ 分文件编译时不吃这套 —— 在 Makefile 里用 -include 强塞给所有编译单元。
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <algorithm>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
