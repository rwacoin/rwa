// Copyright (c) 2018-2020 The Rwa Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoin.h>

#include <util/translation.h>
#include <util/url.h>

#include <QCoreApplication>

#include <functional>
#include <string>

#ifdef _DEBUG
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\boost_filesystem-vc140-mt-gd.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\boost_thread-vc140-mt-gd.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\libzmq-mt-sgd-4_3_4.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\leveldb.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\libdb48.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\event.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\double-conversion.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\debug\\lib\\sqlite3.lib")
#else
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\boost_filesystem-vc140-mt.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\boost_thread-vc140-mt.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\libzmq-mt-s-4_3_4.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\leveldb.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\libdb48.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\sqlite3.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\event.lib")
#pragma comment(lib, "..\\..\\x64-windows-static\\lib\\double-conversion.lib")
#endif

/** Translate string to current locale using Qt. */
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN = [](const char* psz) {
    return QCoreApplication::translate("bitcoin-core", psz).toStdString();
};
UrlDecodeFn* const URL_DECODE = urlDecode;

int wmain(int argc, char* argv[]) { return GuiMain(argc, argv); }
