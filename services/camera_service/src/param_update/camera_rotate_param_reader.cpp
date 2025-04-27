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
    if (!CameraRoateParamSignTool::VerifyFileSign(PUBKEY_PATH, certFile, canonicalPath)) {
        MEDIA_ERR_LOG("signToolManager verify failed %{public}s,%{public}s, %{public}s", PUBKEY_PATH.c_str(),
            certFile.c_str(), canonicalPath);
        return false;
    }
    std::ifstream file(canonicalPath);
    free(canonicalPath);
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
    CHECK_ERROR_RETURN_RET_LOG(realpath((cfgDirPath + filePathStr).c_str(), canonicalPath) == nullptr, false,
        "VerifyParamFile filePathStr is irregular");
    MEDIA_INFO_LOG("VerifyParamFile ,filePathStr:%{public}s", filePathStr.c_str());
    std::string absFilePath = std::string(canonicalPath);
    std::string manifestFile = cfgDirPath + "/MANIFEST.MF";
    char *canonicalPathManifest = realpath(manifestFile.c_str(), nullptr);
    if (canonicalPathManifest == nullptr) {
        return false;
    }
    std::ifstream file(canonicalPathManifest);
    free(canonicalPathManifest);
    std::string line;
    std::string sha256Digest;

    CHECK_ERROR_RETURN_RET_LOG(
        !file.good(), false, "manifestFile is not good,manifestFile:%{public}s", manifestFile.c_str());
    std::ifstream paramFile(absFilePath);
    CHECK_ERROR_RETURN_RET_LOG(
        !paramFile.good(), false, "paramFile is not good,paramFile:%{public}s", absFilePath.c_str());

    while (std::getline(file, line)) {
        std::string nextline;
        if (line.find("Name: " + filePathStr) != std::string::npos) {
            std::getline(file, nextline);
            sha256Digest = SplitStringWithPattern(nextline, ':')[1];
            TrimString(sha256Digest);
            break;
        }
    }
    CHECK_ERROR_RETURN_RET_LOG(sha256Digest.empty(), false, "VerifyParamFile failed ,sha256Digest is empty");
    std::tuple<int, std::string> ret = CameraRoateParamSignTool::CalcFileSha256Digest(absFilePath);
    CHECK_ERROR_RETURN_RET_LOG(
        std::get<0>(ret) != 0, false, "CalcFileSha256Digest failed,error : %{public}d ", std::get<0>(ret));
    if (sha256Digest == std::get<1>(ret)) {
        return true;
    } else {
        return false;
    }
}

std::string CameraRoateParamReader::GetVersionInfoStr(const std::string &filePathStr)
{
    char canonicalPath[PATH_MAX + 1] = {0x00};
    CHECK_ERROR_RETURN_RET_LOG(realpath(filePathStr.c_str(), canonicalPath) == nullptr, DEFAULT_VERSION,
        "GetVersionInfoStr filepath is irregular");
    std::ifstream file(canonicalPath);
    CHECK_ERROR_RETURN_RET_LOG(
        !file.good(), DEFAULT_VERSION, "VersionFilePath is not good,FilePath:%{public}s", filePathStr.c_str());
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
    CHECK_ERROR_RETURN_RET_LOG(
        localVersion.size() != VERSION_LEN || pathVersion.size() != VERSION_LEN, false, "Version num not valid");
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
