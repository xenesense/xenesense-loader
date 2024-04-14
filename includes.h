#pragma once
#include <cstdint>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <psapi.h>
#include <bitset>
#include <vector>
#include <sstream>
#include <regex>
#include <random>
#include <iomanip>
#include <fstream>
#include <atlsecurity.h>

#include "sk_crypt.h"
#include "utils/lazy_importer.h"
#include "utils/utils.h"
#include "utils/xor.h"
#include "Driver/Driver.h"
#include "Inject/inject.h"

#include "plus_aes.h"

#pragma comment(lib, "ws2_32.lib")