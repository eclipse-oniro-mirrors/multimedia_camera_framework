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

#ifndef CAMERA_DEFERRED_PHOTO_MODULETEST_H
#define CAMERA_DEFERRED_PHOTO_MODULETEST_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "gtest/gtest.h"

#include "camera_error_code.h"
#include "input/camera_device.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/capture_output.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "session/capture_session.h"
#include "test_common.h"

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "image_receiver.h"
#include "nativetoken_kit.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
class PhotoListenerModuleTest;

class CameraDeferredPhotoModuleTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    std::vector<SceneMode> GetSupportedSceneModes(sptr<CameraDevice>& camera);
    sptr<CaptureOutput> CreatePreviewOutput(Profile& previewProfile);
    sptr<PhotoOutput> CreatePhotoOutputWithoutSurfaceId(Profile& photoProfile);
    sptr<PhotoOutput> CreatePhotoOutputWithSurfaceId(Profile& photoProfile);
    int32_t AddInput(sptr<CaptureInput>& cameraInput);
    int32_t AddPreviewOutput(sptr<CaptureOutput>& previewOutput);
    int32_t AddPhotoOutput(sptr<PhotoOutput>& photoOutput);
    int32_t CreateAndOpenCameraInput();
    int32_t RegisterPhotoAvailableCallback();
    int32_t RegisterPhotoAssetAvailableCallback();
    int32_t Start();
    int32_t Capture();

    sptr<CameraManager> cameraManager_{nullptr};
    std::vector<sptr<CameraDevice>> cameras_;
    sptr<CameraOutputCapability> outputCapability_{nullptr};
    std::vector<Profile> previewProfiles_;
    std::vector<Profile> photoProfiles_;
    sptr<CaptureOutput> previewOutput_{nullptr};
    sptr<PhotoOutput> photoOutput_{nullptr};
    std::shared_ptr<Media::ImageReceiver> imageReceiver_{nullptr};
    sptr<Surface> previewSurface_{nullptr};
    sptr<Surface> photoSurface_{nullptr};
    sptr<PhotoListenerModuleTest> photoListener_{nullptr};
    sptr<CaptureInput> cameraInput_{nullptr};
    sptr<CaptureSession> captureSession_{nullptr};

    bool isInitSuccess_{false};
    bool isCameraInputOpened_{false};
    bool isCameraInputAdded_{false};
    bool isPreviewOutputAdded_{false};
    bool isPhotoOutputAdded_{false};
    bool isSessionStarted_{false};
};

class PhotoListenerModuleTest : public IBufferConsumerListener {
public:
    PhotoListenerModuleTest(wptr<PhotoOutput> photoOutput);
    ~PhotoListenerModuleTest() = default;
    void OnBufferAvailable() override;
    void WaitForPhotoCallbackAndSetTimeOut();

    int32_t calldeCount_;
    wptr<PhotoOutput> wPhotoOutput_;
    std::mutex mtx_;
    std::condition_variable cv_;
};
} // CameraStandard
} // OHOS
#endif // CAMERA_DEFERRED_PHOTO_MODULETEST_H
