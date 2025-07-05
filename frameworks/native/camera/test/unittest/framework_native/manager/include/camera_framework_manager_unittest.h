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

#ifndef CAMERA_FRAMEWORK_MANAGER_UNITTEST_H
#define CAMERA_FRAMEWORK_MANAGER_UNITTEST_H

#include "gtest/gtest.h"
#include "camera_manager.h"
#include "camera_manager_for_sys.h"

namespace OHOS {
namespace CameraStandard {

class CameraMuteListenerTest : public CameraMuteListener {
public:
    CameraMuteListenerTest() = default;
    virtual ~CameraMuteListenerTest() = default;
    virtual void OnCameraMute(bool muteMode) const {};
};

class TorchListenerTest : public TorchListener {
public:
    TorchListenerTest() = default;
    virtual ~TorchListenerTest() = default;
    virtual void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const {};
};

class FoldListenerTest : public FoldListener {
public:
    FoldListenerTest() = default;
    virtual ~FoldListenerTest() = default;
    virtual void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const {};
};

class TorchListenerImpl : public TorchListener {
public:
    TorchListenerImpl() = default;
    virtual ~TorchListenerImpl() = default;
    virtual void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const;
};

class IDeferredVideoProcSessionCallbackTest : public IDeferredVideoProcSessionCallback {
public:
    IDeferredVideoProcSessionCallbackTest() = default;
    virtual ~IDeferredVideoProcSessionCallbackTest() = default;
    virtual void OnProcessVideoDone(const std::string& videoId, const sptr<IPCFileDescriptor> ipcFd) {};
    virtual void OnError(const std::string& videoId, const DpsErrorCode errorCode) {};
    virtual void OnStateChanged(const DpsStatusCode status) {};
};

class CameraManagerCallbackTest : public CameraManagerCallback {
public:
    CameraManagerCallbackTest() = default;
    virtual ~CameraManagerCallbackTest() = default;
    void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const {};
    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const {};
};

class CameraManagerTest : public CameraManager {
public:
    bool ConvertMetaToFwkMode(const HDI::Camera::V1_3::OperationMode opMode, SceneMode &scMode);
    bool ConvertFwkToMetaMode(const SceneMode scMode, HDI::Camera::V1_3::OperationMode &opMode);
};

class CameraFrameWorkManagerUnit : public testing::Test {
public:
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t VIDEO_DEFAULT_WIDTH = 640;
    static const int32_t VIDEO_DEFAULT_HEIGHT = 360;
    static const int32_t FIXEDFPS_DEFAULT = 30;
    static const int32_t MINFPS_DEFAULT = 12;
    static const int32_t MAXFPS_DEFAULT = 30;
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<CameraManagerForSys> cameraManagerForSys_ = nullptr;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);
};

}
}

#endif