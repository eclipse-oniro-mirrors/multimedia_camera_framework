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

#ifndef CAMERA_MOVEING_PHOTO_MODULETEST_H
#define CAMERA_MOVEING_PHOTO_MODULETEST_H

#include <vector>

#include "gtest/gtest.h"
#include "input/camera_manager.h"
#include "media_asset_manager_capi.h"
#include "moving_photo_capi.h"
#include "session/capture_session.h"
#include "surface.h"
#include "utils/camera_buffer_handle_utils.h"

namespace OHOS {
namespace CameraStandard {
const int32_t WAIT_TIME_AFTER_CAPTURE = 1;
const int32_t WAIT_TIME_AFTER_START = 1;
const int32_t WAIT_TIME_CALLBACK = 2;

typedef void (*PhotoOutputTest_PhotoAssetAvailable)(PhotoOutput* photoOutput, OH_MediaAsset* photoAsset);

class PhotoListenerTest : public IBufferConsumerListener {
public:
    explicit PhotoListenerTest(PhotoOutput* photoOutput, sptr<Surface> surface);
    ~PhotoListenerTest();
    void OnBufferAvailable() override;
    void SetCallbackFlag(uint8_t callbackFlag);
    void SetPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback);
    void UnregisterPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback);

private:
    void ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, CameraBufferExtraData extraData,
        bool isHighQuality, int64_t timestamp);
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer);
    void CreateMediaLibrary(sptr<SurfaceBuffer> surfaceBuffer, BufferHandle *bufferHandle,
        CameraBufferExtraData extraData, bool isHighQuality, std::string &uri,
        int32_t &cameraShotType, std::string &burstKey, int64_t timestamp);
    CameraBufferExtraData GetCameraBufferExtraData(const sptr<SurfaceBuffer> &surfaceBuffer);

    PhotoOutput* photoOutput_;
    sptr<Surface> photoSurface_;
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback_ = nullptr;
    uint8_t callbackFlag_ = 0;
};

class CameraMovingPhotoModuleTest : public testing::Test {
public:
    static OH_MediaAsset *mediaAsset_;
    static OH_MovingPhoto *movingPhoto_;
    static OH_MediaAssetManager *mediaAssetManager_;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

protected:
    void UpdateCameraOutputCapability(int32_t modeName = 0);

    int32_t CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput);
    int32_t CreatePhotoOutputWithoutSurface(Profile &profile, sptr<PhotoOutput> &photoOutput);

    int32_t RegisterPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback);
    int32_t UnregisterPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback);

    static void onPhotoAssetAvailable(PhotoOutput *photoOutput, OH_MediaAsset *mediaAsset);
    static void onMovingPhotoDataPrepared(MediaLibrary_ErrorCode result, MediaLibrary_RequestId requestId,
        MediaLibrary_MediaQuality mediaQuality, MediaLibrary_MediaContentType type, OH_MovingPhoto* movingPhoto);
    int32_t MediaAssetManagerRequestMovingPhoto(OH_MediaLibrary_OnMovingPhotoDataPrepared callback);
    void ReleaseMediaAsset();

    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;

    uint8_t callbackFlag_ = 0;
    sptr<Surface> photoSurface_;
    sptr<PhotoListenerTest> photoListener_;

    sptr<CameraInput> input_;
    std::vector<sptr<CameraDevice>> cameras_;
    sptr<CameraManager> manager_;
    sptr<CaptureSession> session_;

    sptr<PreviewOutput> previewOutput_;
    sptr<PhotoOutput> photoOutput_;
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_MOVEING_PHOTO_MODULETEST_H