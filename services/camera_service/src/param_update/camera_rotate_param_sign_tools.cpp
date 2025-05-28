/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "camera_rotate_param_sign_tools.h"

#include <fstream> // ifstream所需
#include <iostream>
#include <sstream> // stringstream
#include "camera_log.h"
#include "file_ex.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
bool CameraRoateParamSignTool::VerifyFileSign(const std::string &pubKeyPath, const std::string &signPath,
    const std::string &digestPath)
{
    if (!(CheckPathExist(pubKeyPath.c_str()) && CheckPathExist(signPath.c_str()) &&
        CheckPathExist(digestPath.c_str()))) {
        MEDIA_ERR_LOG("file not exist");
        return false;
    }

    const std::string signStr = GetFileStream(signPath);
    const std::string digeststr = GetFileStream(digestPath);

    BIO *bio = BIO_new_file(pubKeyPath.c_str(), "r");

    RSA *pubKey = RSA_new();

    CHECK_ERROR_RETURN_RET_LOG(
        PEM_read_bio_RSA_PUBKEY(bio, &pubKey, NULL, NULL) == NULL, false, "get pubKey is failed");

    bool verify = false;
    if (!(pubKey == NULL || signStr.empty() || digeststr.empty())) {
        verify = VerifyRsa(pubKey, digeststr, signStr);
    } else {
        MEDIA_ERR_LOG("pubKey == NULL || signStr.empty() || digeststr.empty()");
    }
    BIO_free(bio);
    RSA_free(pubKey);
    return verify;
}

bool CameraRoateParamSignTool::VerifyRsa(RSA *pubKey, const std::string &digest, const std::string &sign)
{
    EVP_PKEY *evpKey = NULL;
    EVP_MD_CTX *ctx = NULL;
    evpKey = EVP_PKEY_new();
    CHECK_ERROR_RETURN_RET_LOG(evpKey == nullptr, false, "evpKey == nullptr");
    CHECK_ERROR_RETURN_RET_LOG(EVP_PKEY_set1_RSA(evpKey, pubKey) != 1, false, "EVP_PKEY_set1_RSA(evpKey, pubKey) != 1");
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    if (ctx == nullptr) {
        MEDIA_ERR_LOG("ctx == nullptr");
        EVP_PKEY_free(evpKey);
        return false;
    }
    // warnning：需要与签名的hash算法一致，当前使用的是 sha256withrsa ，需要选择 EVP_sha256()
    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        MEDIA_ERR_LOG("EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) != 1");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1) {
        MEDIA_ERR_LOG("EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyFinal(ctx, (unsigned char *)sign.c_str(), sign.size(), evpKey) != 1) {
        MEDIA_ERR_LOG("EVP_VerifyFinal(ctx, (unsigned char *)sign.c_str(), sign.size(), evpKey) != 1)");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_free(evpKey);
    EVP_MD_CTX_free(ctx);
    return true;
}

std::tuple<int, std::string> CameraRoateParamSignTool::CalcFileSha256Digest(const std::string &fpath)
{
    auto res = std::make_unique<unsigned char[]>(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    auto sha256Update = [ctx = &ctx](char *buf, size_t len) { SHA256_Update(ctx, buf, len); };
    int err = ForEachFileSegment(fpath, sha256Update);
    SHA256_Final(res.get(), &ctx);
    if (err) {
        return { err, "" };
    }
    std::string dist;
    CalcBase64(res.get(), SHA256_DIGEST_LENGTH, dist);
    return { err, dist };
};

int CameraRoateParamSignTool::ForEachFileSegment(const std::string &fpath, std::function<void(char *, size_t)> executor)
{
    char canonicalPath[PATH_MAX + 1] = {0x00};
    CHECK_ERROR_RETURN_RET_LOG(
        realpath(fpath.c_str(), canonicalPath) == nullptr, errno, "ForEachFileSegment filepath is irregular");
    std::unique_ptr<FILE, decltype(&fclose)> filp = { fopen(canonicalPath, "r"), fclose };
    if (!filp) {
        return errno;
    }
    const size_t pageSize { getpagesize() };
    auto buf = std::make_unique<char[]>(pageSize);
    size_t actLen;
    do {
        actLen = fread(buf.get(), 1, pageSize, filp.get());
        if (actLen > 0) {
            executor(buf.get(), actLen);
        }
    } while (actLen == pageSize);

    return ferror(filp.get()) ? errno : 0;
};

void CameraRoateParamSignTool::CalcBase64(uint8_t *input, uint32_t inputLen, std::string &encodedStr)
{
    size_t expectedLength = 4 * ((inputLen + 2) / 3); // 4 3 is Fixed algorithm
    encodedStr.resize(expectedLength);
    int lengthTemp = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(&encodedStr[0]), input, inputLen);
    CHECK_ERROR_RETURN(lengthTemp < 0);
    size_t actualLength = static_cast<size_t>(lengthTemp);
    encodedStr.resize(actualLength);
    MEDIA_INFO_LOG("expectedLength = %{public}zu, actualLength = %{public}zu", expectedLength, actualLength);
}
// LCOV_EXCL_STOP
} // namespace CameraStandardParamSignTool
} // namespace OHOS
