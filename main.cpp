#include "includes.h"

#include "aes.h"
#include "loader.h"

#include "service.h"

WSADATA wsaData;
SOCKET sock;

std::string path;

void save_file_to_disk(const char* filename, const std::string& content) {
    FILE* file = std::fopen(filename, "wb");
    if (file) {
        std::fwrite(content.c_str(), sizeof(char), content.size(), file);
        std::fclose(file);
    }
    else {
    }
}

void delete_it_self() {
    //const char* executableName = path.c_str(); // Change this to your executable's name
    //
    //// Create a batch script to delete the executable and the batch script itself
    //std::ofstream selfDeleteScript(_("C:\\Windows\\self_delete.bat"));
    //selfDeleteScript << _("@echo off\n");
    //selfDeleteScript << _("ping 127.0.0.1 -n 2 > nul\n"); // Give some time to terminate the program
    //selfDeleteScript << _("del %0\n"); // Delete the batch script
    //selfDeleteScript << _("del ") << executableName << "\n"; // Delete the executable
    //selfDeleteScript.close();
    //
    //// Execute the batch script and terminate the program
    //std::system(_("C:\\Windows\\self_delete.bat"));
    //
    //return;
}
void load_cheat() {
   
    srand((unsigned)time(NULL) * GetCurrentThreadId());

    while (true) {
     
        std::string listener = loader::get().button_listener();

       

        if (listener == _("1")) {
           

            memset(service::driver_name, 0, sizeof(service::driver_name));
            static const char alphanum[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int len = rand() % 20 + 10;
            for (int i = 0; i < len; ++i)
                service::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
            
            
            auto temp_path = service::GetFullTempPath();
            temp_path.append(L"\\corelele.sys");
            std::string driver_path(temp_path.begin(), temp_path.end());
            
            
            std::string file = loader::get().download_file(skCrypt("991").decrypt());
            
            save_file_to_disk(driver_path.c_str(), file);
            
            
            if (!service::RegisterAndStart(temp_path)) {
                auto driver_str(skCrypt("Failed to load the driver"));
                SAFE_CALL(MessageBoxA)(0,driver_str,0,0);
                driver_str.encrypt();
                loader::get().diconnect_from_server();
                LI_FN(Sleep)(1000);
                throw 37;
            }
            
            auto bbb = loader::get().download_file(_("10"));
            
            
            while (!LI_FN(GetAsyncKeyState).forwarded_safe_cached()(VK_F2)) {
                LI_FN(Sleep)(10);
            }
            
            
            Inject* inject = new Inject();
            
            //if (!inject->inject_module_from_path_to_process_by_name((BYTE*)bbb.data(), skCrypt("VALORANT-Win64-Shipping.exe"))) {
            if (!inject->inject_module_from_path_to_process_by_name(L"D:\\Srcs\\xenesense\\xene-valorant\\x64\\Release\\xene-valorant.dll", skCrypt("VALORANT-Win64-Shipping.exe"))) {
                
                auto driver_str(skCrypt("Failed to inject"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
            }
            
            
            if (!service::UnloadSignedDriver()) {
            
                auto driver_str(skCrypt("Error\nCode 0x9"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
                SAFE_CALL(Sleep)(3000);
            
            }

            loader::get().diconnect_from_server();

            delete_it_self();

            throw 37;

        }
        if (listener == _("3")) {
            std::string file = loader::get().download_file(skCrypt("999").decrypt());

            memset(service::driver_name, 0, sizeof(service::driver_name));
            static const char alphanum[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int len = rand() % 20 + 10;
            for (int i = 0; i < len; ++i)
                service::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];


            auto temp_path = service::GetFullTempPath();
            temp_path.append(L"\\corelele.sys");
            std::string driver_path(temp_path.begin(), temp_path.end());

            save_file_to_disk(driver_path.c_str(), file);


            if (!service::RegisterAndStart(temp_path)) {
                auto driver_str(skCrypt("Failed to load the driver"));
                SAFE_CALL(MessageBoxA)(0, driver_str, 0, 0);
                driver_str.encrypt();
                loader::get().diconnect_from_server();
                LI_FN(Sleep)(1000);
                throw 37;
            }


           

            auto bbb = loader::get().download_file(_("20"));


            while (!LI_FN(GetAsyncKeyState).forwarded_safe_cached()(VK_F2)) {
                LI_FN(Sleep)(10);
            }



            

            Inject* inject = new Inject();

            if (!inject->inject_module_from_path_to_process_by_name_fn((BYTE*)bbb.data(), skCrypt("RustClient.exe"))) {
            //if (!inject->inject_module_from_path_to_process_by_name_fn(L"C:\\dll.dll", skCrypt("RustClient.exe"))) {
                auto driver_str(skCrypt("Failed to in inject"));
                SAFE_CALL(MessageBoxA)(0,driver_str.decrypt(),0,0);
                driver_str.encrypt();
            }



            if (!service::UnloadSignedDriver()) {
            
                auto driver_str(skCrypt("Error\nCode 0x9"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
                SAFE_CALL(Sleep)(3000);
            
            }

            loader::get().diconnect_from_server();

            delete_it_self();

            throw 37;
        }
        if (listener == _("5")) {
            std::string file = loader::get().download_file(skCrypt("997").decrypt());

            memset(service::driver_name, 0, sizeof(service::driver_name));
            static const char alphanum[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int len = rand() % 20 + 10;
            for (int i = 0; i < len; ++i)
                service::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];


            auto temp_path = service::GetFullTempPath();
            temp_path.append(L"\\corelele.sys");
            std::string driver_path(temp_path.begin(), temp_path.end());

            save_file_to_disk(driver_path.c_str(), file);


            if (!service::RegisterAndStart(temp_path)) {
                auto driver_str(skCrypt("Failed to load the driver"));
                SAFE_CALL(MessageBoxA)(0, driver_str, 0, 0);
                driver_str.encrypt();
                loader::get().diconnect_from_server();
                LI_FN(Sleep)(1000);
                throw 37;
            }




            auto bbb = loader::get().download_file(_("30"));


            while (!LI_FN(GetAsyncKeyState).forwarded_safe_cached()(VK_F2)) {
                LI_FN(Sleep)(10);
            }





            Inject* inject = new Inject();

            if (!inject->inject_module_from_path_to_process_by_name_fn((BYTE*)bbb.data(), skCrypt("RustClient.exe"))) {
                //if (!inject->inject_module_from_path_to_process_by_name_fn(L"C:\\dll.dll", skCrypt("RustClient.exe"))) {
                auto driver_str(skCrypt("Failed to in inject"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
            }



            if (!service::UnloadSignedDriver()) {

                auto driver_str(skCrypt("Error\nCode 0x9"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
                SAFE_CALL(Sleep)(3000);

            }

            loader::get().diconnect_from_server();

            delete_it_self();

            throw 37;
        }
        if (listener == _("6")) {


            memset(service::driver_name, 0, sizeof(service::driver_name));
            static const char alphanum[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int len = rand() % 20 + 10;
            for (int i = 0; i < len; ++i)
                service::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];


            auto temp_path = service::GetFullTempPath();
            temp_path.append(L"\\corelele.sys");
            std::string driver_path(temp_path.begin(), temp_path.end());


            std::string file = loader::get().download_file(skCrypt("991").decrypt());

            save_file_to_disk(driver_path.c_str(), file);


            if (!service::RegisterAndStart(temp_path)) {
                auto driver_str(skCrypt("Failed to load the driver"));
                SAFE_CALL(MessageBoxA)(0, driver_str, 0, 0);
                driver_str.encrypt();
                loader::get().diconnect_from_server();
                LI_FN(Sleep)(1000);
                throw 37;
            }

            auto bbb = loader::get().download_file(_("100"));


            while (!LI_FN(GetAsyncKeyState).forwarded_safe_cached()(VK_F2)) {
                LI_FN(Sleep)(10);
            }


            Inject* inject = new Inject();

            //if (!inject->inject_module_from_path_to_process_by_name((BYTE*)bbb.data(), skCrypt("VALORANT-Win64-Shipping.exe"))) {
            if (!inject->inject_module_from_path_to_process_by_name(L"D:\\Srcs\\xenesense\\xene-valorant\\x64\\Release\\xene-valorant.dll", skCrypt("VALORANT-Win64-Shipping.exe"))) {

                auto driver_str(skCrypt("Failed to inject"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
            }


            if (!service::UnloadSignedDriver()) {

                auto driver_str(skCrypt("Error\nCode 0x9"));
                SAFE_CALL(MessageBoxA)(0, driver_str.decrypt(), 0, 0);
                driver_str.encrypt();
                SAFE_CALL(Sleep)(3000);

            }

            loader::get().diconnect_from_server();

            delete_it_self();

            throw 37;

        }
        Sleep(500);
    }
}

int WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nShowCmd
)
//int main()
{
    
    char buffer[MAX_PATH];
    SAFE_CALL(GetModuleFileNameA)(NULL, buffer, MAX_PATH);

    path = buffer;
   
    SAFE_CALL(ShowWindow)(SAFE_CALL(GetConsoleWindow)(), SW_HIDE);

    loader::get().connect_to_server();

    while (!SAFE_CALL(GetAsyncKeyState)(VK_F5)) {

        auto response = loader::get().recieve_data();
        if (response == _("set_hwid")) {
            loader::get().diconnect_from_server();
            SAFE_CALL(MessageBoxA)(0, skCrypt("New hwid has been bound to the account\nPlease re-open the loader to continue"), 0, 0);
            throw 37;
        }
        if (response == _("invalid_hwid")) {
            loader::get().diconnect_from_server();
            SAFE_CALL(MessageBoxA)(0, skCrypt("Invalid hwid"), 0, 0);
            throw 37;
        }
        else if (response == "success") {
            break;
        }
        SAFE_CALL(Sleep)(500);

    }
 
    SAFE_CALL(CreateThread)(0, 0, (LPTHREAD_START_ROUTINE)load_cheat, 0, 0, 0);

    while (loader::get().valid()) {
        SAFE_CALL(Sleep)(5000);
    }

    loader::get().diconnect_from_server();


    delete_it_self();

    //Inject* inject = new Inject();
    //
    //inject->inject_module_from_path_to_process_by_name(L"D:\\Srcs\\xenesense\\xene-fortnite\\x64\\Release\\1.dll", skCrypt("FortniteClient-Win64-Shipping.exe"));
}