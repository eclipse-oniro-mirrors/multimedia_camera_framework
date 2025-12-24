/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_ROTATE_SERVICE_SERVICES_INCLUDE_CAMERA_ROTATE_PARAM_MANAGER_H
#define OHOS_CAMERA_ROTATE_SERVICE_SERVICES_INCLUDE_CAMERA_ROTATE_PARAM_MANAGER_H

#include <string>
#include <mutex>
#include <map>
#include <functional>
#include <memory>

#include "camera_rotate_param_reader.h"
#include "common_event_subscriber.h"
#include "parser.h"
#include "camera_xml_parser.h"
#include "want.h"

namespace OHOS {
namespace CameraStandard {

class CameraRoateParamManager {
public:
    static CameraRoateParamManager& GetInstance();
    void InitParam();
    int GetFeatureSwitchConfig();
    void SubscriberEvent();
    void UnSubscriberEvent();
    void OnReceiveEvent(const AAFwk::Want &want);
    std::vector<CameraRotateStrategyInfo> GetCameraRotateStrategyInfos();

private:
    class ParamCommonEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        explicit ParamCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
            CameraRoateParamManager &registry)
            : CommonEventSubscriber(subscriberInfo), registry_(registry)
        {}
        ~ParamCommonEventSubscriber() = default;

        void OnReceiveEvent(const EventFwk::CommonEventData &data) override
        {
            registry_.OnReceiveEvent(data.GetWant());
        }

    private:
        CameraRoateParamManager &registry_;
    };
    CameraRoateParamManager() = default;
    ~CameraRoateParamManager() = default;
    void ReloadParam();
    std::string LoadVersion();
    void LoadParamStr();
    std::string GetVersion();
    bool LoadConfiguration(const std::string &filepath);
    void Destroy();
    void InitDefaultConfig();
    void CopyFileToLocal();
    bool DoCopy(const std::string& src, const std::string& des);
    void VerifyCloudFile(const std::string& prePath);
    void HandleParamUpdate(const AAFwk::Want &want)const;
    bool ParseInternal(std::shared_ptr<CameraXmlNode> curNode);
    void ParserStrategyInfo(std::shared_ptr<CameraXmlNode> curNode);

    std::mutex strategyInfosMutex_;
    std::shared_ptr<CameraXmlNode> curNode_ = nullptr;
    std::vector<CameraRotateStrategyInfo> cameraRotateStrategyInfos_ = {};
    std::mutex mutxVerify;
    std::shared_ptr<CameraRoateParamReader> paramReader = nullptr;
    int totalFeatureSwitch = 0;
    using EventHandle = std::function<void(const OHOS::AAFwk::Want &)>;
    typedef void (CameraRoateParamManager::*HandleEventFunc)(const AAFwk::Want &) const;
    std::map<std::string, EventHandle> eventHandles_;
    std::map<std::string, HandleEventFunc> handleEventFunc_;
    std::shared_ptr<ParamCommonEventSubscriber> subscriber_ = nullptr;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ROTATE_SERVICE_SERVICES_INCLUDE_CAMERA_ROTATE_PARAM_MANAGER_H
