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
 
#ifndef OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_SIGN_TOOL_H
#define OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_SIGN_TOOL_H

#include <string>
#include "camera_util.h"

#include <openssl/bio.h> // bio
#include <openssl/evp.h> // evp
#include <openssl/pem.h> // PEM_read_bio_RSA_PUBKEY
#include <openssl/rsa.h> // rsa

namespace OHOS {
namespace CameraStandard {

class CameraRoateParamSignTool {
public:
    CameraRoateParamSignTool() = default;
    ~CameraRoateParamSignTool() = default;

    static void CalcBase64(uint8_t *input, uint32_t inputLen, std::string &encodedStr);
    static bool VerifyFileSign(const std::string &pubKeyPath,
        const std::string &signPath, const std::string &digestPath);
    static std::tuple<int, std::string> CalcFileSha256Digest(const std::string &fpath);
    static bool VerifyRsa(RSA *pubKey, const std::string &digest, const std::string &sign);
    static int ForEachFileSegment(const std::string &fpath, std::function<void(char *, size_t)> executor);
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_SIGN_TOOL_H
