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
 
#include "camera_rotate_param_manager.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <common_event_data.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include "common_event_subscriber.h"
#include "camera_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

namespace {
static int32_t RETRY_SUBSCRIBER = 3;
static const int8_t DECIMAL = 10;
const bool NEED_PARAM_VERIFY = true;
const std::string CONFIG_FILE_NAME = "camera_rotate_strategy.xml";
const std::string CAMERA_CFG_PATH = "/sys_prod/etc/camera/" + CONFIG_FILE_NAME;
const std::string EVENT_INFO_TYPE = "type";
const std::string EVENT_INFO_SUBTYPE = "subtype";
const std::string RECEIVE_UPDATE_PERMISSION = "ohos.permission.RECEIVE_UPDATE_MESSAGE";
const std::string CONFIG_UPDATED_ACTION = "usual.event.DUE_SA_CFG_UPDATED";
const std::string CONFIG_TYPE = "camera";

const char* XML_CAMERA_STRATEGY = "strategy";
const char* XML_CAMERA_BUDLE_NAME = "bundleName";
const char* XML_CAMERA_WIDE_VALUE = "wideValue";
const char* XML_CAMERA_ROTATE_DEGREE = "rotateDegree";
const char* XML_CAMERA_FPS = "fps";
}

CameraRoateParamManager& CameraRoateParamManager::GetInstance()
{
    static CameraRoateParamManager instance;
    return instance;
}

void CameraRoateParamManager::InitParam()
{
    MEDIA_INFO_LOG("InitParam");
    if (paramReader == nullptr) {
        paramReader = std::make_shared<CameraRoateParamReader>();
    }
    if (paramReader != nullptr) {
        std::string cloudVersion = paramReader->GetPathVersion(); // 云推版本号
        std::vector<std::string> cloudVersionNum;
        if (!paramReader->VersionStrToNumber(cloudVersion, cloudVersionNum)) {
            MEDIA_ERR_LOG("VersionStrToNumber error , pathVersion is invalid");
            return;
        }
        std::string localVersion = LoadVersion(); // 本地参数版本号/system/etc/camera/version.txt
        std::vector<std::string> localVersionNum;
        if (!paramReader->VersionStrToNumber(localVersion, localVersionNum)) {
            MEDIA_ERR_LOG("VersionStrToNumber error , currentVersion is invalid");
            return;
        }
        MEDIA_INFO_LOG(
            "currentVersion: %{public}s pathVersion :%{public}s", localVersion.c_str(), cloudVersion.c_str());
        if (paramReader->CompareVersion(localVersionNum, cloudVersionNum)) {
            ReloadParam();
        }
    }
    LoadParamStr(); // 读取本地配置
};

void CameraRoateParamManager::ReloadParam()
{
    MEDIA_DEBUG_LOG("called");
    if (paramReader == nullptr) {
        MEDIA_ERR_LOG("paramReader is nullptr");
        return;
    }
    std::string path = paramReader->GetConfigFilePath();
    MEDIA_INFO_LOG("GetConfigFilePath, path: %{public}s ", path.c_str());
    // 判断是路径是否在下载路径, 下载路径需要增加安全校验
    if (NEED_PARAM_VERIFY && path.find(PARAM_UPDATE_ABS_PATH) != std::string::npos) {
        VerifyCloudFile(PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR);
    }
};

void CameraRoateParamManager::VerifyCloudFile(const std::string& prePath)
{
    if (paramReader == nullptr) {
        MEDIA_ERR_LOG("paramReader is nullptr");
        return;
    }
    // 校验参数签名是否合法
    std::string certFile = prePath + "/CERT.ENC"; // 获取签名文件
    std::string verifyFile = prePath + "/CERT.SF"; // 获取待验证的文件
    std::string manifestFile = prePath + "/MANIFEST.MF"; // 文件列表文件
    std::lock_guard<std::mutex> lock(mutxVerify);
    if (!paramReader->VerifyCertSfFile(certFile, verifyFile, manifestFile)) {
        MEDIA_ERR_LOG(" VerifyCertSfFile  error , param is invalid");
        return;
    }
    std::string cfgDir = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR;
    // 校验参数文件是否合法
    if (!paramReader->VerifyParamFile(cfgDir, VERSION_FILE_NAME)) {
        MEDIA_ERR_LOG("verify version file error , param is invalid");
        return;
    }
    if (!paramReader->VerifyParamFile(cfgDir, CONFIG_FILE_NAME)) {
        MEDIA_ERR_LOG("verify param file error , param is invalid");
        return;
    }
    // 拷贝参数到本地
    CopyFileToLocal();
}

void CameraRoateParamManager::CopyFileToLocal()
{
    if (!DoCopy(PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + VERSION_FILE_NAME,
        CAMERA_SERVICE_ABS_PATH + VERSION_FILE_NAME)) {
        MEDIA_ERR_LOG("version.txt copy to local error");
        return;
    }
    if (!DoCopy(PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + CONFIG_FILE_NAME,
        CAMERA_SERVICE_ABS_PATH + CONFIG_FILE_NAME)) {
        MEDIA_ERR_LOG("ofbs_config.json copy to local error");
        return;
    }
    MEDIA_INFO_LOG("CopyFileToLocal success");
}

bool CameraRoateParamManager::DoCopy(const std::string& src, const std::string& des)
{
    if (!CheckPathExist(src.c_str())) {
        MEDIA_ERR_LOG("srcPath is invalid");
        return false;
    }
    if (CheckPathExist(des.c_str())) {
        MEDIA_INFO_LOG("des has file");
        if (!RemoveFile(des)) {
            MEDIA_ERR_LOG("rm des file error");
            return false;
        }
    }
    std::filesystem::path sPath(src);
    std::filesystem::path dPath(des);
    std::error_code errNo;
    const auto copyOptions = std::filesystem::copy_options::overwrite_existing |
        std::filesystem::copy_options::recursive |
        std::filesystem::copy_options::skip_symlinks;
    std::filesystem::copy(sPath, dPath, copyOptions, errNo);
    // if has some error in copy, record errno
    if (errNo.value()) {
        MEDIA_ERR_LOG("copy failed errno:%{public}d", errNo.value());
        return false;
    }
    MEDIA_INFO_LOG("copy success");
    return true;
}

std::string CameraRoateParamManager::LoadVersion()
{
    if (paramReader == nullptr) {
        MEDIA_ERR_LOG("paramReader is nullptr");
        return "";
    }
    std::string filePath = CAMERA_SERVICE_ABS_PATH + VERSION_FILE_NAME; // 优先沙箱找
    std::ifstream file(filePath);
    if (!file.good()) {
        return paramReader->GetVersionInfoStr(ABS_CONTENT_FILE_PATH + VERSION_FILE_NAME); // 服务配置路径
    }
    return paramReader->GetVersionInfoStr(filePath);
}

void CameraRoateParamManager::LoadParamStr()
{
    std::string filePath = CAMERA_SERVICE_ABS_PATH + CONFIG_FILE_NAME;
    std::ifstream file(filePath);
    if (!file.good()) {
        LoadConfiguration(CAMERA_CFG_PATH);
        return;
    }
    LoadConfiguration(filePath);
}

bool CameraRoateParamManager::LoadConfiguration(const std::string &filepath)
{
    curNode_ = CameraXmlNode::Create();
    int32_t ret = curNode_->Config(filepath.c_str(), nullptr, 0);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("Not found camera_rotate_strategy.xml!");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(strategyInfosMutex_);
        cameraRotateStrategyInfos_.clear();
    }
    bool result = ParseInternal(curNode_->GetCopyNode());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "Camera rotate strategy xml parse failed.");
    Destroy();
    return true;
}

void CameraRoateParamManager::Destroy()
{
    curNode_->FreeDoc();
    curNode_->CleanUpParser();
}

bool CameraRoateParamManager::ParseInternal(std::shared_ptr<CameraXmlNode> curNode)
{
    for (; curNode->IsNodeValid(); curNode->MoveToNext()) {
        if (!curNode->IsElementNode()) {
            continue;
        }
        if (curNode->CompareName(XML_CAMERA_STRATEGY)) {
            ParserStrategyInfo(curNode->GetCopyNode());
        } else {
            ParseInternal(curNode->GetChildrenNode());
        }
    }
    return true;
}

void CameraRoateParamManager::ParserStrategyInfo(std::shared_ptr<CameraXmlNode> curNode)
{
    std::lock_guard<std::mutex> lock(strategyInfosMutex_);
    if (curNode->IsNodeValid() && curNode->IsElementNode()) {
        CameraRotateStrategyInfo info = {};
        curNode->GetProp(XML_CAMERA_BUDLE_NAME, info.bundleName);

        std::string pValue;
        float wideValue = -1.0;
        curNode->GetProp(XML_CAMERA_WIDE_VALUE, pValue);
        char* endPtr;
        wideValue = std::strtof(pValue.c_str(), &endPtr);
        if (*endPtr != '\0' || pValue.empty()) {
            wideValue = -1.0;
        }
        info.wideValue = wideValue;
        endPtr = nullptr;

        int rotateDegree = -1;
        curNode->GetProp(XML_CAMERA_ROTATE_DEGREE, pValue);
        long result = strtol(pValue.c_str(), &endPtr, DECIMAL);

        if (*endPtr != '\0' || pValue.empty()) {
            rotateDegree = -1;
        } else {
            rotateDegree = static_cast<int16_t>(result);
        }
        info.rotateDegree = rotateDegree;

        int16_t fps = -1;
        curNode->GetProp(XML_CAMERA_FPS, pValue);
        endPtr = nullptr;
        result = strtol(pValue.c_str(), &endPtr, DECIMAL);

        if (*endPtr != '\0' || pValue.empty()) {
            fps = -1;
        } else {
            fps = static_cast<int16_t>(result);
        }
        info.fps = fps;
        cameraRotateStrategyInfos_.push_back(info);
        MEDIA_INFO_LOG("ParserStrategyInfo: bundleName:%{public}s, wideValue:%{public}f, "
            "rotateDegree:%{public}d, fps:%{public}d",
            info.bundleName.c_str(), info.wideValue, info.rotateDegree, info.fps);
    }
}

void CameraRoateParamManager::InitDefaultConfig()
{
    totalFeatureSwitch = 1;
    cameraRotateStrategyInfos_.clear();
}

std::vector<CameraRotateStrategyInfo> CameraRoateParamManager::GetCameraRotateStrategyInfos()
{
    return cameraRotateStrategyInfos_;
}

void CameraRoateParamManager::SubscriberEvent()
{
    MEDIA_INFO_LOG("SubscriberEvent start.");
    // 可以添加多个事件监听
    handleEventFunc_["usual.event.DUE_SA_CFG_UPDATED"] = &CameraRoateParamManager::HandleParamUpdate;
    for (auto it = handleEventFunc_.begin(); it != handleEventFunc_.end(); ++it) {
        MEDIA_INFO_LOG("Add event: %{public}s", it->first.c_str());
        eventHandles_.emplace(it->first, std::bind(it->second, this, std::placeholders::_1));
    }
    if (subscriber_) {
        MEDIA_ERR_LOG("Common Event is already subscribered!");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    for (auto &event : handleEventFunc_) {
        MEDIA_INFO_LOG("Add event: %{public}s", event.first.c_str());
        matchingSkills.AddEvent(event.first);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission(RECEIVE_UPDATE_PERMISSION);
    subscriber_ = std::make_shared<ParamCommonEventSubscriber>(subscribeInfo, *this);

    int32_t retry = RETRY_SUBSCRIBER;
    do {
        bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
        if (subscribeResult) {
            MEDIA_INFO_LOG("SubscriberEvent success.");
            return;
        } else {
            MEDIA_ERR_LOG("SubscriberEvent failed, retry %{public}d", retry);
            retry--;
            sleep(1);
        }
    } while (retry);
    MEDIA_INFO_LOG("SubscriberEvent failed.");
}

void CameraRoateParamManager::UnSubscriberEvent()
{
    MEDIA_INFO_LOG("UnSubscriberEvent start.");
    eventHandles_.clear();
    handleEventFunc_.clear();
    if (subscriber_) {
        bool subscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        MEDIA_INFO_LOG("subscribeResult = %{public}d", subscribeResult);
        subscriber_ = nullptr;
    }
    MEDIA_INFO_LOG("UnSubscriberEvent end.");
}

void CameraRoateParamManager::OnReceiveEvent(const AAFwk::Want &want)
{
    std::string action = want.GetAction();
    auto it = eventHandles_.find(action);
    if (it == eventHandles_.end()) {
        MEDIA_INFO_LOG("Ignore event: %{public}s", action.c_str());
        return;
    }
    MEDIA_INFO_LOG("Handle event: %{public}s", action.c_str());
    it->second(want);
}

void CameraRoateParamManager::HandleParamUpdate(const AAFwk::Want &want) const
{
    std::string action = want.GetAction();
    std::string type = want.GetStringParam(EVENT_INFO_TYPE);
    std::string subtype = want.GetStringParam(EVENT_INFO_SUBTYPE);
    MEDIA_INFO_LOG("recive param update event: %{public}s ,%{public}s ,%{public}s ", action.c_str(), type.c_str(),
        subtype.c_str());
    if (action != CONFIG_UPDATED_ACTION || type != CONFIG_TYPE) {
        MEDIA_ERR_LOG("invalid param update info: %{public}s, %{public}s, %{public}s",
            action.c_str(), type.c_str(), subtype.c_str());
        return;
    }
    CameraRoateParamManager::GetInstance().InitParam();
}

}
}
