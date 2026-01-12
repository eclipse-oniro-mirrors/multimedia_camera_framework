/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "photo_buffer_consumer_unittest.h"
#include "photo_buffer_consumer.h"
#include "surface_buffer.h"
#include "picture_proxy.h"
#include "camera_log.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {

class MockStreamCapturePhotoCallback : public IStreamCapturePhotoCallback {
public:
    MOCK_METHOD3(OnPhotoAvailable, int32_t(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw));
    MOCK_METHOD1(OnPhotoAvailable, int32_t(std::shared_ptr<PictureIntf> picture));
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

void PhotoBufferConsumerUnitTest::SetUpTestCase() {}

void PhotoBufferConsumerUnitTest::TearDownTestCase() {}

void PhotoBufferConsumerUnitTest::SetUp() {}

void PhotoBufferConsumerUnitTest::TearDown() {}

#ifdef CAMERA_CAPTURE_YUV
/*
 * Feature: PhotoBufferConsumer
 * Function: StartWaitAuxiliaryTask
 * SubFunction: NA
 * FunctionPoints: Immediate assembly when auxiliaryCount == 1
 * EnvConditions: NA
 * CaseDescription: Call StartWaitAuxiliaryTask with auxiliaryCount = 1. The picture is assembled immediately,
 * and all internal states associated with the captureId (including captureIdCountMap_) are cleaned up after processing.
 * Therefore, the captureId should no longer exist in captureIdCountMap_.
 */
HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxiliaryTask_001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(format, width, height);
    int32_t captureId = 1001;
    int32_t auxiliaryCount = 1;
    int64_t timestamp = 123456789ULL;

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(surfaceBuffer, nullptr);
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->StartWaitAuxiliaryTask(captureId, auxiliaryCount, timestamp, surfaceBuffer);
    // After immediate assembly, all states for captureId are cleaned up.
    EXPECT_EQ(streamCapture->captureIdCountMap_[captureId], 0U);
}

/*
 * Feature: PhotoBufferConsumer
 * Function: StartWaitAuxiliaryTask
 * SubFunction: NA
 * FunctionPoints: Watchdog activation when auxiliaryCount > 1
 * EnvConditions: NA
 * CaseDescription: Call StartWaitAuxiliaryTask with auxiliaryCount = 2. Since more than one buffer is needed,
 * the method should not assemble immediately but instead start a watchdog timer to wait for additional buffers.
 */
HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxiliaryTask_002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(format, width, height);
    int32_t captureId = 1002;
    int32_t auxiliaryCount = 2;
    int64_t timestamp = 123456790ULL;

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(surfaceBuffer, nullptr);
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->StartWaitAuxiliaryTask(captureId, auxiliaryCount, timestamp, surfaceBuffer);
    // AssembleDeferredPicture() is NOT called
    EXPECT_EQ(streamCapture->captureIdCountMap_[captureId], auxiliaryCount);
}

/*
 * Feature: PhotoBufferConsumer
 * Function: AssembleDeferredPicture
 * SubFunction: NA
 * FunctionPoints: Picture assembly and callback triggering
 * EnvConditions: Valid captureId with pre-injected picture proxy
 * CaseDescription: Directly call AssembleDeferredPicture with a valid captureId that has associated picture data.
 * The function should trigger OnPhotoAvailable on the stream capture interface and clean up internal state.
 */
HWTEST_F(PhotoBufferConsumerUnitTest, AssembleDeferredPicture_001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(format, width, height);

    int32_t captureId = 1003;
    int64_t timestamp = 123456791ULL;

    auto* mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;

    int32_t ret = streamCapture->SetPhotoAvailableCallback(mockCallback);
    ASSERT_EQ(ret, 0) << "Failed to set photo available callback";

    auto picture = PictureProxy::CreatePictureProxy();
    ASSERT_NE(picture, nullptr);

    sptr<SurfaceBuffer> mainBuf = SurfaceBuffer::Create();
    ASSERT_NE(mainBuf, nullptr);
    picture->Create(mainBuf);

    streamCapture->captureIdPictureMap_[captureId] = picture;

    EXPECT_CALL(*mockCallbackRaw, OnPhotoAvailable(testing::_))
        .WillOnce(testing::Return(0));

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->AssembleDeferredPicture(timestamp, captureId);

    EXPECT_EQ(streamCapture->captureIdPictureMap_.count(captureId), 0U);
}

/*
 * Feature: PhotoBufferConsumer
 * Function: CleanAfterTransPicture
 * SubFunction: NA
 * FunctionPoints: Internal state cleanup by captureId
 * EnvConditions: Pre-populated internal maps for a given captureId
 * CaseDescription: Call CleanAfterTransPicture with a captureId that has entries in multiple internal maps.
 * The function should remove all associated entries without crashing.
 */
HWTEST_F(PhotoBufferConsumerUnitTest, CleanAfterTransPicture_001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(format, width, height);

    int32_t captureId = 1004;
    auto picture = PictureProxy::CreatePictureProxy();
    ASSERT_NE(picture, nullptr);

    streamCapture->captureIdPictureMap_[captureId] = picture;
    streamCapture->captureIdCountMap_[captureId] = 3;
    streamCapture->captureIdAuxiliaryCountMap_[captureId] = 2;
    streamCapture->captureIdHandleMap_[captureId] = 999;

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->CleanAfterTransPicture(captureId);
    EXPECT_EQ(streamCapture->captureIdPictureMap_.count(captureId), 0U);
}
#endif
} // namespace CameraStandard
} // namespace OHOS