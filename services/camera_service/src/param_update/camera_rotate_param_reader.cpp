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
 
#include "camera_rotate_param_reader.h"

#include <memory>
#include <iostream>
#include <fstream>

#include "camera_log.h"
#include "camera_util.h"
#ifdef CONFIG_POLICY_EXT_ENABLE
#include "config_policy_param_upgrade_path.h"
#include "config_policy_utils.h"
#endif
#include "camera_rotate_param_sign_tools.h"

namespace OHOS {
namespace CameraStandard {

namespace {
const std::string PUBKEY_PATH = ABS_CONTENT_FILE_PATH + PUB_KEY_NAME;
constexpr int VERSION_LEN = 4;
constexpr int DEC = 10;
}

// 获取高版本配置路径
std::string CameraRoateParamReader::GetConfigFilePath()
{
#ifdef CONFIG_POLICY_EXT_ENABLE
    std::lock_guard<std::mutex> lock(custMethodLock);
    ::HwCustSetDataSourceType(HW_CUST_TYPE_SYSTEM);
    std::string cfgDir = CAMERA_ROTATE_CFG_DIR;
    //期望data/service/el1/public/update/param_service/install/system/etc/camera/version.txt
    ParamVersionFileInfo *paramVersionFileInfo = ::GetDownloadCfgFile(cfgDir.c_str(), cfgDir.c_str());
    if (paramVersionFileInfo == NULL) {
        MEDIA_ERR_LOG("NULL ptr, can not found txt in path : %{public}s", cfgDir.c_str());
        return {};
    }
    if (!paramVersionFileInfo->found) {
        MEDIA_ERR_LOG("not found, can not found version txt in path : %{public}s", cfgDir.c_str());
        free(paramVersionFileInfo);
        return {};
    }
    std::string path = std::string(paramVersionFileInfo->path);
    MEDIA_INFO_LOG("GetConfigFilePath path:%{public}s", path.c_str());
    free(paramVersionFileInfo);
    return path;
#else
     return PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR;
#endif
};

// 获取路径下版本信息
std::string CameraRoateParamReader::GetPathVersion()
{
    std::string path = GetConfigFilePath();
    MEDIA_INFO_LOG("GetPathVersion:%{public}s", path.c_str());
    if (path.find(PARAM_UPDATE_ABS_PATH) != std::string::npos) {
        return GetVersionInfoStr(PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + VERSION_FILE_NAME);
    }
    return GetVersionInfoStr(CAMERA_ROTATE_CFG_DIR + VERSION_FILE_NAME); // 返回本地的默认路径system/etc/camera/
};

// 校验下载的参数文件是否合法
bool CameraRoateParamReader::VerifyCertSfFile(
    const std::string &certFile, const std::string &verifyFile, const std::string &manifestFile)
{
    char *canonicalPath = realpath(verifyFile.c_str(), nullptr);
    if (canonicalPath == nullptr) {
        return false;
    }
    // 验证CERT.SF文件是否合法
    if (!CameraRoateParamSignTool::VerifyFileSign(PUBKEY_PATH, certFile, verifyFile)) {
        MEDIA_ERR_LOG("signToolManager verify failed %{public}s,%{public}s, %{public}s", PUBKEY_PATH.c_str(),
            certFile.c_str(), verifyFile.c_str());
        return false;
    }
    std::ifstream file(verifyFile);
    if (!file.good()) {
        MEDIA_ERR_LOG("Verify is not good,verifyFile:%{public}s", verifyFile.c_str());
        return false;
    };
    std::string line;
    std::string sha256Digest;
    std::getline(file, line);
    file.close();
    sha256Digest = SplitStringWithPattern(line, ':')[1];
    TrimString(sha256Digest);
    std::tuple<int, std::string> ret = CameraRoateParamSignTool::CalcFileSha256Digest(manifestFile);
    std::string manifestDigest = std::get<1>(ret);
    if (sha256Digest == manifestDigest) {
        return true;
    }
    return false;
};

// 校验下载的参数文件的完整性
bool CameraRoateParamReader::VerifyParamFile(const std::string& cfgDirPath, const std::string &filePathStr)
{
    char canonicalPath[PATH_MAX + 1] = {0x00};
    if (realpath((cfgDirPath + filePathStr).c_str(), canonicalPath) == nullptr) {
        return false;
    }
    MEDIA_INFO_LOG("VerifyParamFile ,filePathStr:%{public}s", filePathStr.c_str());
    std::string absFilePath = std::string(canonicalPath);
    std::string manifestFile = cfgDirPath + "/MANIFEST.MF";
    char *canonicalPathManifest = realpath(manifestFile.c_str(), nullptr);
    if (canonicalPathManifest == nullptr) {
        return false;
    }
    std::ifstream file(canonicalPathManifest);
    std::string line;
    std::string sha256Digest;

    if (!file.good()) {
        MEDIA_ERR_LOG("manifestFile is not good,manifestFile:%{public}s", manifestFile.c_str());
        return false;
    }
    std::ifstream paramFile(absFilePath);
    if (!paramFile.good()) {
        MEDIA_ERR_LOG("paramFile is not good,paramFile:%{public}s", absFilePath.c_str());
        return false;
    }

    while (std::getline(file, line)) {
        std::string nextline;
        if (line.find("Name: " + filePathStr) != std::string::npos) {
            std::getline(file, nextline);
            sha256Digest = SplitStringWithPattern(nextline, ':')[1];
            TrimString(sha256Digest);
            break;
        }
    }
    if (sha256Digest.empty()) {
        MEDIA_ERR_LOG("VerifyParamFile failed ,sha256Digest is empty");
        return false;
    }
    std::tuple<int, std::string> ret = CameraRoateParamSignTool::CalcFileSha256Digest(absFilePath);
    if (std::get<0>(ret) != 0) {
        MEDIA_ERR_LOG("CalcFileSha256Digest failed,error : %{public}d ", std::get<0>(ret));
        return false;
    }
    if (sha256Digest == std::get<1>(ret)) {
        return true;
    } else {
        return false;
    }
}

std::string CameraRoateParamReader::GetVersionInfoStr(const std::string &filePathStr)
{
    char canonicalPath[PATH_MAX + 1] = {0x00};
    if (realpath(filePathStr.c_str(), canonicalPath) == nullptr) {
        MEDIA_ERR_LOG("GetVersionInfoStr filepath is irregular");
        return DEFAULT_VERSION;
    }
    std::ifstream file(canonicalPath);
    if (!file.good()) {
        MEDIA_ERR_LOG("VersionFilePath is not good,FilePath:%{public}s", filePathStr.c_str());
        return DEFAULT_VERSION;
    }
    std::string line;
    std::getline(file, line);
    std::string versionStr = SplitStringWithPattern(line, '=')[1];
    TrimString(versionStr);
    return versionStr;
};

bool CameraRoateParamReader::VersionStrToNumber(const std::string &versionStr, std::vector<std::string> &versionNum)
{
    versionNum.clear();
    versionNum = SplitStringWithPattern(versionStr, '.');
    return versionNum.size() == VERSION_LEN;
}

bool CameraRoateParamReader::CompareVersion(
    const std::vector<std::string> &localVersion, const std::vector<std::string> &pathVersion)
{
    if (localVersion.size() != VERSION_LEN || pathVersion.size() != VERSION_LEN) {
        MEDIA_ERR_LOG("Version num not valid");
        return false;
    }
    for (int i = 0; i < VERSION_LEN; i++) {
        if (localVersion[i] != pathVersion[i]) {
            int ret = strtol(localVersion[i].c_str(), nullptr, DEC) < strtol(pathVersion[i].c_str(), nullptr, DEC);
            return ret;
        }
    }
    return false;
}

}
}
