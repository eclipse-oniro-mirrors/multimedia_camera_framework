/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HCAMERA_SERVICE_UNITTEST_H
#define HCAMERA_SERVICE_UNITTEST_H

#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "input/camera_manager.h"
#include "output/sketch_wrapper.h"
#include "portrait_session.h"

namespace OHOS {
namespace CameraStandard {

class ITorchServiceCallbackTest : public ITorchServiceCallback {
public:
    virtual int32_t OnTorchStatusChange(const TorchStatus status)
    {
        return 0;
    };

    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };


    DECLARE_INTERFACE_DESCRIPTOR(u"ITorchServiceCallback");
};

class IFoldServiceCallbackTest : public IFoldServiceCallback {
public:
    virtual int32_t OnFoldStatusChanged(const FoldStatus status)
    {
        return 0;
    };

    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };


    DECLARE_INTERFACE_DESCRIPTOR(u"IFoldServiceCallback");
};

class ICameraMuteServiceCallbackTest : public ICameraMuteServiceCallback {
public:
    virtual int32_t OnCameraMute(bool muteMode)
    {
        return 0;
    };

    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ICameraMuteServiceCallbackTest");
};

class ICameraBrokerTest : public ICameraBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");

    virtual int32_t NotifyCloseCamera(std::string cameraId)
    {
        return 0;
    };
    virtual int32_t NotifyMuteCamera(bool muteMode)
    {
        return 0;
    };
    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };
};

class ICameraServiceCallbackTest : public ICameraServiceCallback {
public:
    virtual int32_t OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status,
        const std::string& bundleName = "")
    {
        return 0;
    };
    virtual int32_t OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status)
    {
        return 0;
    };
    virtual sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ICameraServiceCallbackTest");
};

class HCameraServiceUnit :  public testing::Test {
public:
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t VIDEO_DEFAULT_WIDTH = 640;
    static const int32_t VIDEO_DEFAULT_HEIGHT = 360;
    uint64_t tokenId_;
    int32_t uid_;
    int32_t userId_;
    sptr<HCameraHostManager> cameraHostManager_;
    sptr<CameraManager> cameraManager_;
    sptr<HCameraService> cameraService_;
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> pDevice_;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);
};

}
}

#endif