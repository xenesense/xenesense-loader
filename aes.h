#pragma once
#pragma once
#define AES_METHOD "AES-256-CBC"


__inline std::vector<std::string> split(const std::string str, const std::string regex_str) {
    // TODO: we gotta find a proper way to split the string using regex, it takes much memory
    std::regex regexz(regex_str);
    std::vector<std::string> list(std::sregex_token_iterator(str.begin(), str.end(), regexz, -1),
        std::sregex_token_iterator());
    return list;
}

inline std::string string_to_hex(const std::string& in) {
    std::stringstream ss;

    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    }

    return ss.str();
}

inline std::string hex_to_string(const std::string& in) {

    std::string output;

    if ((in.length() % 2) != 0) {
        return "";
    }

    size_t cnt = in.length() / 2;

    for (size_t i = 0; cnt > i; ++i) {
        uint32_t s = 0;
        std::stringstream ss;
        ss << std::hex << in.substr(i * 2, 2);
        ss >> s;

        output.push_back(static_cast<unsigned char>(s));
    }

    return output;
}

std::string new_encrypt(std::string in) {
    std::vector<unsigned char> arrayy = {
       0xd5, 0xcb, 0xe0, 0xe2, 0xab, 0xe3, 0xcf, 0xd0, 0xe3, 0xbe, 0xb2,
       0xdf, 0xc1, 0xc3, 0xaf, 0xbc, 0xd1, 0xb3, 0xde, 0xd2, 0xd4, 0xca,
       0xc0, 0xdf, 0xb5, 0xb3, 0xd1, 0xb2, 0xbf, 0xda, 0x9c, 0x9f
    };

    /*for (int i = 0; i < 32; i++) {
        decrypted_aes.push_back(arrayy[i] - 0x69);
    }*/



    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(in.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    std::vector<unsigned char> iv(16);
    {
        std::mt19937_64 eng;
        std::uniform_int_distribution<> dist;

        for (int i = 0; i < 16; i++) iv[i] = dist(eng);
    }

    unsigned char ivArray[16];
    std::copy(iv.begin(), iv.end(), ivArray);

    std::vector<unsigned char> decrypted_aes;
    for (int i = 0; i < 32; i++) {
        decrypted_aes.push_back(arrayy[i] - 0x69);
    }

    plusaes::encrypt_cbc((unsigned char*)in.data(), in.size(), &decrypted_aes[0], decrypted_aes.size(), &ivArray, &encrypted[0], encrypted.size(), true);
    strcpy((char*)&decrypted_aes[0], "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");


    return string_to_hex(std::string(iv.begin(), iv.end())) + ":" + string_to_hex(std::string{ encrypted.begin(), encrypted.end() });
}

std::string new_decrypt(std::string in) {

    std::vector<unsigned char> arrayy = {
       0xd5, 0xcb, 0xe0, 0xe2, 0xab, 0xe3, 0xcf, 0xd0, 0xe3, 0xbe, 0xb2,
       0xdf, 0xc1, 0xc3, 0xaf, 0xbc, 0xd1, 0xb3, 0xde, 0xd2, 0xd4, 0xca,
       0xc0, 0xdf, 0xb5, 0xb3, 0xd1, 0xb2, 0xbf, 0xda, 0x9c, 0x9f
    };

    std::vector<unsigned char> decrypted_aes;
    for (int i = 0; i < 32; i++) {
        decrypted_aes.push_back(arrayy[i] - 0x69);
    }

    auto iv_enc = split(in, ":");
    std::string iv_hex = iv_enc[0];
    std::string encrypted_hex = iv_enc[1];


    //auto splitPos = in.find(_(":"));

    std::string iv = hex_to_string(iv_hex);
    std::string cipherText = hex_to_string(encrypted_hex);




    unsigned char ivData[16];
    std::copy(iv.begin(), iv.end(), ivData);




    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(cipherText.size());
    plusaes::decrypt_cbc((unsigned char*)cipherText.data(), cipherText.size(), &decrypted_aes[0], decrypted_aes.size(), &ivData, &decrypted[0], decrypted.size(), &padded_size);

    strcpy((char*)&decrypted_aes[0], "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");


    return std::string{ decrypted.begin(), decrypted.end() }.substr(0, decrypted.size() - padded_size);

}