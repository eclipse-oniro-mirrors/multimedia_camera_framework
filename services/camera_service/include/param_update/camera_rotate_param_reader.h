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
 
#ifndef OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_READER_H
#define OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_READER_H

#include <string>
#include <mutex>

namespace OHOS {
namespace CameraStandard {

namespace {
const std::string ABS_CONTENT_FILE_PATH = "/system/etc/camera/"; // 本地配置路径通过服务配置
const std::string CAMERA_SERVICE_ABS_PATH = "/data/service/el1/public/camera_service/";  // 本地沙箱路径
const std::string PARAM_UPDATE_ABS_PATH = "/data/service/el1/public/update/param_service/install/";  // 云推下载路径
const std::string PARAM_SERVICE_INSTALL_PATH = "/data/service/el1/public/update/param_service/install/system";
const std::string CAMERA_ROTATE_CFG_DIR = "/etc/camera/";
const std::string PUB_KEY_NAME = "hwkey_param_upgrade_v1.pem";
const std::string VERSION_FILE_NAME = "version.txt";
const std::string DEFAULT_VERSION = "1.0.0.0"; // 版本号非硬编
}

class CameraRoateParamReader {
public:
    CameraRoateParamReader() = default;
    virtual ~CameraRoateParamReader() = default;
    
    virtual std::string GetConfigFilePath();
    virtual bool VerifyCertSfFile(
        const std::string &certFile, const std::string &verifyFile, const std::string &manifestFile);
    virtual bool VerifyParamFile(const std::string &cfgDirPath, const std::string &filePathStr);
    std::string GetPathVersion();
    std::string GetVersionInfoStr(const std::string &filePathStr);
    bool VersionStrToNumber(const std::string &versionStr, std::vector<std::string> &versionNum);
    bool CompareVersion(const std::vector<std::string> &localVersion, const std::vector<std::string> &pathVersion);
private:
    std::mutex custMethodLock;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ROTATE_SERVICE_PARAM_INCLUDE_CAMERA_ROTATE_PARAM_READER_H
