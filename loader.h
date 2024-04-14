#pragma once
#include <Windows.h>
#include "singleton.h"

class loader : public singleton<loader> {
private:
	WSADATA wsaData;
	SOCKET sock;
public:
    int connect_to_server() {
        if (SAFE_CALL(WSAStartup)(MAKEWORD(2, 2), &wsaData) != 0) {
            return -1;
        }

        sock = SAFE_CALL(socket)(2, 1, 0);
        if (sock == 0) {
            SAFE_CALL(WSACleanup)();
            return -1;
        }

        const char* serverIP = _("185.254.97.88");  // Replace with the server's IP address
        int serverPort = 8080;                // Replace with the server's port number

        sockaddr_in serverAddress{};
        serverAddress.sin_family = 2;
        serverAddress.sin_port = htons(serverPort);
        serverAddress.sin_addr.S_un.S_addr = inet_addr(serverIP);

        if (SAFE_CALL(connect)(sock, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == (-1)) {
            SAFE_CALL(closesocket)(sock);
            SAFE_CALL(WSACleanup)();
            return -1;
        }


        return 1;
    }

    bool valid() {
        return true;
    }

    void diconnect_from_server() {
        SAFE_CALL(closesocket)(sock);
        SAFE_CALL(WSACleanup)();
        sock = 0;
    }


    std::string get_hwid() {
        ATL::CAccessToken accessToken;
        ATL::CSid currentUserSid;
        if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
            accessToken.GetUser(&currentUserSid))
            return std::string(CT2A(currentUserSid.Sid()));
        return "none";
    }


    std::string recieve_data() {
        std::string cringe = skCrypt("update_state").decrypt();
        cringe.append(skCrypt("|").decrypt());
        cringe.append(get_hwid());

        std::string bruh = new_encrypt(cringe);

        SAFE_CALL(send)(sock, bruh.c_str(), static_cast<int>(bruh.size()), 0);

        char buffer[4097];
        int bytesRead = SAFE_CALL(recv)(sock, buffer, 4096, 0);

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';  // Null-terminate the received data
            
        }

        std::string str_encrypted(buffer, sizeof(buffer));

        std::string str_decrypted = new_decrypt(str_encrypted);


        return str_decrypted;
    }

    std::string button_listener() {
        std::string cringe = skCrypt("button_press").decrypt();

        std::string bruh = new_encrypt(cringe);

        SAFE_CALL(send)(sock, bruh.c_str(), static_cast<int>(bruh.size()), 0);

        char buffer[4097];
        int bytesRead = SAFE_CALL(recv)(sock, buffer, 4096, 0);

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';  // Null-terminate the received data
            
        }


        std::string str_encrypted(buffer, sizeof(buffer));

        std::string str_decrypted = new_decrypt(str_encrypted);


        return str_decrypted;
    }

    std::string download_file(std::string file_id) {
        std::string cringe;
        cringe.append(_("download_e"));
        cringe.append(_("|"));
        cringe.append(file_id);

        std::string bruh = new_encrypt(cringe);

        SAFE_CALL(send)(sock, bruh.c_str(), static_cast<int>(bruh.size()), 0);
        std::string response;
        char buffer[4096 * 12];
        for (;;) {
            auto length = SAFE_CALL(recv)(sock, buffer, 4096 * 12, 0);
            std::string received = std::string(buffer, length);

            
            if (received.substr(received.length() - 5) == "nigga") {
                response.append(buffer, length - 5);

                //std::cout << received << std::endl;
                break;

            }
            else
            {
                response.append(buffer, length);
            }
        }

        std::string str_decrypted = new_decrypt(response);

        return str_decrypted;
    }

};