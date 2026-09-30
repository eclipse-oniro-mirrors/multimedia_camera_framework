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
#include "photo_asset_buffer_consumer.h"
#include "surface_buffer.h"
#include "picture_proxy.h"
#include "camera_log.h"
#include "camera_surface_buffer_util.h"
#include "buffer_extra_data_impl.h"
#include "sync_fence.h"
#include "surface.h"
#include "video_key_info.h"
#include "watch_dog.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {

namespace {
const int32_t AUX_PHOTO_TEST_WIDTH = 1920;
const int32_t AUX_PHOTO_TEST_HEIGHT = 1080;
const int32_t AUX_PHOTO_TYPE_OXYGEN = 0;
const int32_t AUX_PHOTO_TYPE_PIGMENTATION = 1;

sptr<BufferExtraData> CreateExtraDataWithImageCount(int32_t imageCount)
{
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    extraData->ExtraSet(OHOS::Camera::imageCount, imageCount);
    return extraData;
}

sptr<SurfaceBuffer> CreateAllocatedAuxSurfaceBuffer()
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    if (buffer == nullptr) {
        return nullptr;
    }
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    if (buffer->Alloc(config) != GSERROR_OK) {
        return nullptr;
    }
    return buffer;
}
}

class MockStreamCapturePhotoCallback : public IStreamCapturePhotoCallback {
public:
    MOCK_METHOD3(OnPhotoAvailable, int32_t(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw));
    MOCK_METHOD1(OnPhotoAvailable, int32_t(std::shared_ptr<PictureIntf> picture));
    MOCK_METHOD5(OnPhotoAvailable, int32_t(sptr<SurfaceBuffer> mainBuffer, sptr<SurfaceBuffer> oxygenBuffer,
        sptr<SurfaceBuffer> pigmentationBuffer, int64_t timestamp, bool isRaw));
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class MockStreamCapturePhotoAssetCallback : public IStreamCapturePhotoAssetCallback {
public:
    MOCK_METHOD4(OnPhotoAssetAvailable, ErrCode(int32_t captureId, const std::string& uri,
        int32_t cameraShotType, const std::string& burstKey));
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

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleDeferredPicture_002, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 2015;
    streamCapture->captureIdOxygenMap_[captureId] = SurfaceBuffer::Create();
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->AssembleDeferredPicture(123456802ULL, captureId);
    EXPECT_EQ(streamCapture->captureIdOxygenMap_.count(captureId), 1U);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleDeferredPicture_003, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);

    int32_t captureId = 2016;
    auto picture = PictureProxy::CreatePictureProxy();
    ASSERT_NE(picture, nullptr);
    sptr<SurfaceBuffer> mainBuf = SurfaceBuffer::Create();
    ASSERT_NE(mainBuf, nullptr);
    picture->Create(mainBuf);
    streamCapture->captureIdPictureMap_[captureId] = picture;
    sptr<SurfaceBuffer> oxygenBuffer = CreateAllocatedAuxSurfaceBuffer();
    ASSERT_NE(oxygenBuffer, nullptr);
    sptr<SurfaceBuffer> pigmentationBuffer = CreateAllocatedAuxSurfaceBuffer();
    ASSERT_NE(pigmentationBuffer, nullptr);
    streamCapture->captureIdOxygenMap_[captureId] = oxygenBuffer;
    streamCapture->captureIdPigmentationMap_[captureId] = pigmentationBuffer;

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw, OnPhotoAvailable(testing::_)).WillOnce(testing::Return(0));
    consumer->AssembleDeferredPicture(123456803ULL, captureId);
    EXPECT_EQ(streamCapture->captureIdOxygenMap_[captureId], nullptr);
    EXPECT_EQ(streamCapture->captureIdPigmentationMap_[captureId], nullptr);
    EXPECT_EQ(streamCapture->captureIdPictureMap_.count(captureId), 0U);
}
#endif

HWTEST_F(PhotoBufferConsumerUnitTest, GetArrivedAuxPhotoCount_001, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 2001;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_EQ(consumer->GetArrivedAuxPhotoCount(streamCapture, captureId), 0U);
    streamCapture->captureIdOxygenMap_[captureId] = SurfaceBuffer::Create();
    EXPECT_EQ(consumer->GetArrivedAuxPhotoCount(streamCapture, captureId), 1U);
    streamCapture->captureIdPigmentationMap_[captureId] = SurfaceBuffer::Create();
    EXPECT_EQ(consumer->GetArrivedAuxPhotoCount(streamCapture, captureId), 2U);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_001, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);

    int32_t captureId = 2002;
    int64_t timestamp = 123456792ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw,
        OnPhotoAvailable(_, _, _, _, _)).WillOnce(testing::Return(0));
    consumer->StartWaitAuxPhotoTask(captureId, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_002, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 2003;
    int64_t timestamp = 123456793ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    streamCapture->captureIdMainPhotoMap_[captureId] = mainBuffer;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->StartWaitAuxPhotoTask(captureId, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 1U);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 0U);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_003, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 2004;
    int64_t timestamp = 123456794ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    mainBuffer->SetExtraData(CreateExtraDataWithImageCount(3));
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->StartWaitAuxPhotoTask(captureId, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 1U);
    EXPECT_EQ(streamCapture->captureIdCountMap_[captureId], 2);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 1U);
    DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(streamCapture->captureIdHandleMap_[captureId]);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_004, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);

    int32_t captureId = 2005;
    int64_t timestamp = 123456795ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    mainBuffer->SetExtraData(CreateExtraDataWithImageCount(3));
    streamCapture->captureIdAuxiliaryCountMap_[captureId] = 2;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw,
        OnPhotoAvailable(_, _, _, _, _)).WillOnce(testing::Return(0));
    consumer->StartWaitAuxPhotoTask(captureId, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdAuxiliaryCountMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_005, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 2006;
    int64_t timestamp = 123456796ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    mainBuffer->SetExtraData(CreateExtraDataWithImageCount(2));
    streamCapture->captureIdAuxiliaryCountMap_[captureId] = -1;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->StartWaitAuxPhotoTask(captureId, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 1U);
    EXPECT_EQ(streamCapture->captureIdCountMap_[captureId], 1);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 1U);
    DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(streamCapture->captureIdHandleMap_[captureId]);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, StartWaitAuxPhotoTask_006, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    streamCapture = nullptr;
    int64_t timestamp = 123456797ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    consumer->StartWaitAuxPhotoTask(2007, timestamp, mainBuffer);
    EXPECT_EQ(streamCapture, nullptr);
}

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleCompressedPhotoWithAux_001, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);
    int32_t captureId = 2008;
    int64_t timestamp = 123456798ULL;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->AssembleCompressedPhotoWithAux(timestamp, captureId);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleCompressedPhotoWithAux_002, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);

    int32_t captureId = 2009;
    int64_t timestamp = 123456799ULL;
    sptr<SurfaceBuffer> mainBuffer = SurfaceBuffer::Create();
    ASSERT_NE(mainBuffer, nullptr);
    sptr<SurfaceBuffer> oxygenBuffer = SurfaceBuffer::Create();
    ASSERT_NE(oxygenBuffer, nullptr);
    sptr<SurfaceBuffer> pigmentationBuffer = SurfaceBuffer::Create();
    ASSERT_NE(pigmentationBuffer, nullptr);
    streamCapture->captureIdMainPhotoMap_[captureId] = mainBuffer;
    streamCapture->captureIdOxygenMap_[captureId] = oxygenBuffer;
    streamCapture->captureIdPigmentationMap_[captureId] = pigmentationBuffer;
    streamCapture->captureIdHandleMap_[captureId] = 1;
    streamCapture->captureIdAuxiliaryCountMap_[captureId] = 2;
    streamCapture->captureIdCountMap_[captureId] = 2;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw,
        OnPhotoAvailable(_, _, _, _, _)).WillOnce(testing::Return(0));
    consumer->AssembleCompressedPhotoWithAux(timestamp, captureId);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdOxygenMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdPigmentationMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdAuxiliaryCountMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdCountMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleCompressedPhotoWithAux_003, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    ASSERT_EQ(streamCapture->SetPhotoAvailableCallback(mockCallback), 0);

    int32_t captureId = 2010;
    int64_t timestamp = 123456800ULL;
    streamCapture->captureIdMainPhotoMap_[captureId] = nullptr;
    streamCapture->captureIdOxygenMap_[captureId] = nullptr;
    streamCapture->captureIdPigmentationMap_[captureId] = nullptr;
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->AssembleCompressedPhotoWithAux(timestamp, captureId);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, AssembleCompressedPhotoWithAux_004, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(CAMERA_FORMAT_YUV_420_SP, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    streamCapture = nullptr;
    int64_t timestamp = 123456801ULL;
    consumer->AssembleCompressedPhotoWithAux(timestamp, 2011);
    EXPECT_EQ(streamCapture, nullptr);
}

HWTEST_F(PhotoBufferConsumerUnitTest, ExecuteOnBufferAvailable_AuxPhoto_001, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(OHOS_CAMERA_FORMAT_JPEG, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    std::vector<int32_t> auxPhotoTypes = {AUX_PHOTO_TYPE_OXYGEN, AUX_PHOTO_TYPE_PIGMENTATION};
    ASSERT_EQ(streamCapture->SetAutoAuxiliaryPhotosDeliveryEnabled(auxPhotoTypes, true), CAMERA_OK);

    int32_t captureId = 2012;
    ASSERT_NE(streamCapture->surface_, nullptr);
    sptr<IBufferProducer> producer = streamCapture->surface_->GetProducer();
    ASSERT_NE(producer, nullptr);
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    sptr<SurfaceBuffer> requestBuffer = nullptr;
    sptr<SyncFence> requestFence = SyncFence::InvalidFence();
    ASSERT_EQ(producer->RequestBuffer(requestBuffer, requestFence, config), GSERROR_OK);
    ASSERT_NE(requestBuffer, nullptr);
    sptr<BufferExtraData> extraData = requestBuffer->GetExtraData();
    ASSERT_NE(extraData, nullptr);
    extraData->ExtraSet(OHOS::Camera::captureId, captureId);
    extraData->ExtraSet(OHOS::Camera::imageCount, 3);
    ASSERT_EQ(producer->FlushBuffer(requestBuffer, requestFence, config), GSERROR_OK);

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    consumer->ExecuteOnBufferAvailable();
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 1U);
    EXPECT_EQ(streamCapture->captureIdCountMap_[captureId], 2);
    EXPECT_EQ(streamCapture->captureIdHandleMap_.count(captureId), 1U);
    DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(streamCapture->captureIdHandleMap_[captureId]);
    streamCapture->CleanAuxPhotoState(captureId);
}

HWTEST_F(PhotoBufferConsumerUnitTest, ExecuteOnBufferAvailable_AuxPhoto_002, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(OHOS_CAMERA_FORMAT_JPEG, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    streamCapture->photoAvaiableCallback_.Set(mockCallback);
    std::vector<int32_t> auxPhotoTypes = {AUX_PHOTO_TYPE_OXYGEN};
    ASSERT_EQ(streamCapture->SetAutoAuxiliaryPhotosDeliveryEnabled(auxPhotoTypes, true), CAMERA_OK);

    int32_t captureId = 2013;
    streamCapture->captureIdAuxDegradeMap_[captureId] = 1;
    ASSERT_NE(streamCapture->surface_, nullptr);
    sptr<IBufferProducer> producer = streamCapture->surface_->GetProducer();
    ASSERT_NE(producer, nullptr);
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    sptr<SurfaceBuffer> requestBuffer = nullptr;
    sptr<SyncFence> requestFence = SyncFence::InvalidFence();
    ASSERT_EQ(producer->RequestBuffer(requestBuffer, requestFence, config), GSERROR_OK);
    ASSERT_NE(requestBuffer, nullptr);
    sptr<BufferExtraData> extraData = requestBuffer->GetExtraData();
    ASSERT_NE(extraData, nullptr);
    extraData->ExtraSet(OHOS::Camera::captureId, captureId);
    extraData->ExtraSet(OHOS::Camera::imageCount, 3);
    ASSERT_EQ(producer->FlushBuffer(requestBuffer, requestFence, config), GSERROR_OK);

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw, OnPhotoAvailable(_, _, _)).WillOnce(testing::Return(0));
    consumer->ExecuteOnBufferAvailable();
    EXPECT_EQ(streamCapture->captureIdAuxDegradeMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, ExecuteOnBufferAvailable_AuxPhoto_003, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(OHOS_CAMERA_FORMAT_JPEG, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    auto mockCallbackRaw = new MockStreamCapturePhotoCallback();
    ASSERT_NE(mockCallbackRaw, nullptr);
    sptr<IStreamCapturePhotoCallback> mockCallback = mockCallbackRaw;
    streamCapture->photoAvaiableCallback_.Set(mockCallback);

    int32_t captureId = 2014;
    ASSERT_NE(streamCapture->surface_, nullptr);
    sptr<IBufferProducer> producer = streamCapture->surface_->GetProducer();
    ASSERT_NE(producer, nullptr);
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    sptr<SurfaceBuffer> requestBuffer = nullptr;
    sptr<SyncFence> requestFence = SyncFence::InvalidFence();
    ASSERT_EQ(producer->RequestBuffer(requestBuffer, requestFence, config), GSERROR_OK);
    ASSERT_NE(requestBuffer, nullptr);
    sptr<BufferExtraData> extraData = requestBuffer->GetExtraData();
    ASSERT_NE(extraData, nullptr);
    extraData->ExtraSet(OHOS::Camera::captureId, captureId);
    extraData->ExtraSet(OHOS::Camera::imageCount, 1);
    ASSERT_EQ(producer->FlushBuffer(requestBuffer, requestFence, config), GSERROR_OK);

    auto consumer = std::make_shared<PhotoBufferConsumer>(streamCapture, false);
    EXPECT_CALL(*mockCallbackRaw, OnPhotoAvailable(_, _, _)).WillOnce(testing::Return(0));
    consumer->ExecuteOnBufferAvailable();
    EXPECT_EQ(streamCapture->captureIdMainPhotoMap_.count(captureId), 0U);
}

HWTEST_F(PhotoBufferConsumerUnitTest, PhotoAssetBufferConsumer_CleanAuxState_001, TestSize.Level0)
{
    sptr<HStreamCapture> streamCapture =
        new (std::nothrow) HStreamCapture(OHOS_CAMERA_FORMAT_JPEG, AUX_PHOTO_TEST_WIDTH, AUX_PHOTO_TEST_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);
    std::vector<int32_t> auxPhotoTypes = {AUX_PHOTO_TYPE_OXYGEN};
    ASSERT_EQ(streamCapture->SetAutoAuxiliaryPhotosDeliveryEnabled(auxPhotoTypes, true), CAMERA_OK);
    auto mockAssetCallbackRaw = new MockStreamCapturePhotoAssetCallback();
    ASSERT_NE(mockAssetCallbackRaw, nullptr);
    streamCapture->photoAssetAvaiableCallback_ = mockAssetCallbackRaw;

    int32_t captureId = 2017;
    streamCapture->captureIdAuxDegradeMap_[captureId] = 1;
    streamCapture->captureIdOxygenMap_[captureId] = SurfaceBuffer::Create();
    streamCapture->captureIdPigmentationMap_[captureId] = SurfaceBuffer::Create();
    ASSERT_NE(streamCapture->surface_, nullptr);
    sptr<IBufferProducer> producer = streamCapture->surface_->GetProducer();
    ASSERT_NE(producer, nullptr);
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    sptr<SurfaceBuffer> requestBuffer = nullptr;
    sptr<SyncFence> requestFence = SyncFence::InvalidFence();
    ASSERT_EQ(producer->RequestBuffer(requestBuffer, requestFence, config), GSERROR_OK);
    ASSERT_NE(requestBuffer, nullptr);
    sptr<BufferExtraData> extraData = requestBuffer->GetExtraData();
    ASSERT_NE(extraData, nullptr);
    extraData->ExtraSet(OHOS::Camera::captureId, captureId);
    extraData->ExtraSet(OHOS::Camera::imageCount, 1);
    ASSERT_EQ(producer->FlushBuffer(requestBuffer, requestFence, config), GSERROR_OK);

    auto consumer = std::make_shared<PhotoAssetBufferConsumer>(streamCapture);
    EXPECT_CALL(*mockAssetCallbackRaw, OnPhotoAssetAvailable(captureId, _, _, _)).WillOnce(testing::Return(0));
    consumer->ExecuteOnBufferAvailable();
    EXPECT_EQ(streamCapture->captureIdAuxDegradeMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdOxygenMap_.count(captureId), 0U);
    EXPECT_EQ(streamCapture->captureIdPigmentationMap_.count(captureId), 0U);
}
} // namespace CameraStandard
} // namespace OHOS