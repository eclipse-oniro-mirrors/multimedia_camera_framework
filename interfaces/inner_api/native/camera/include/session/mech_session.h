/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H
#define OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H

#include <refbase.h>

#include "mech_session_callback_stub.h"
#include "imech_session.h"
#include "input/camera_death_recipient.h"
#include "metadata_common_utils.h"

namespace OHOS {
namespace CameraStandard {

class MechSessionCallback : public RefBase {
public:
    MechSessionCallback() = default;
    virtual ~MechSessionCallback() = default;
    virtual void OnFocusTrackingInfo(FocusTrackingMetaInfo info) = 0;
    virtual void OnCaptureSessionConfiged(CaptureSessionInfo captureSessionInfo);
    virtual void OnZoomInfoChange(int sessionid, ZoomInfo zoomInfo);
    virtual void OnSessionStatusChange(int sessionid, bool status);
    virtual void OnMetadataInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) = 0;
};

class MechSession : public RefBase {
public:
    MechSession(sptr<IMechSession> session);
    virtual ~MechSession();

    /**
     * @brief EnableMechDelivery.
     * @return Returns errCode.
     */
    int32_t EnableMechDelivery(bool isEnableMech);

    /**
     * @brief Set the session callback for the MechSession.
     *
     * @param callback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MechSessionCallback> callback);

    /**
     * @brief Get the Callback.
     *
     * @return Returns the pointer to Callback.
     */
    std::shared_ptr<MechSessionCallback> GetCallback();

    /**
     * @brief Releases MechSession instance.
     * @return Returns errCode.
     */
    int32_t Release();
private:
    sptr<IMechSession> GetRemoteSession();
    void SetRemoteSession(sptr<IMechSession> remoteSession);
    void RemoveDeathRecipient();
    void CameraServerDied(pid_t pid);

    std::mutex callbackMutex_;
    std::shared_ptr<MechSessionCallback> appCallback_;
    std::mutex remoteSessionMutex_;
    sptr<IMechSession> remoteSession_ = nullptr;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
};

class MechSessionCallbackImpl : public MechSessionCallbackStub {
public:
    explicit MechSessionCallbackImpl(sptr<MechSession> mechSession)
        : mechSession_(mechSession)
    {
    }

    ~MechSessionCallbackImpl()
    {
        mechSession_ = nullptr;
    }

    ErrCode OnFocusTrackingInfo(int32_t streamId, bool isNeedMirror, bool isNeedFlip,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;
    ErrCode OnCaptureSessionConfiged(const CaptureSessionInfo& captureSessionInfo) override;
    ErrCode OnZoomInfoChange(int32_t sessionid, const ZoomInfo& zoomInfo) override;
    ErrCode OnSessionStatusChange(int32_t sessionid, bool status) override;
    ErrCode OnMetadataInfo(const std::shared_ptr<CameraMetadata>& results) override;

private:
    bool ProcessRectInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
        Rect& rect);
    void PrintFocusTrackingInfo(FocusTrackingMetaInfo& info);
    void PrintCaptureSessionInfo(const CaptureSessionInfo& captureSessionInfo);
    wptr<MechSession> mechSession_;
    uint32_t logCount_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H
