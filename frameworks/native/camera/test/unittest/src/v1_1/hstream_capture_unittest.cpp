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

#include "camera_log.h"
#include "camera_util.h"
#include "hstream_capture_unittest.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

const int32_t HStreamCaptureUnitTest_ONE = 1;
const int32_t HStreamCaptureUnitTest_TWO = 2;
const int32_t HStreamCaptureUnitTest_THREE = 3;
const int32_t HStreamCaptureUnitTest_FOUR = 4;
const uint64_t HStreamCaptureUnitTest_HUNDRED = 100;

class IStreamOperatorFork : public IStreamOperator {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.camera.v1_0.IStreamOperator");

    IStreamOperatorFork(){};
    ~IStreamOperatorFork(){};

    int32_t IsStreamsSupported(OHOS::HDI::Camera::V1_0::OperationMode mode,
        const std::vector<uint8_t>& modeSetting, const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& infos,
            OHOS::HDI::Camera::V1_0::StreamSupportType& type) override
    {
        return SUCCESS;
    }

    int32_t CreateStreams(const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& streamInfos) override
    {
        return SUCCESS;
    }

    int32_t ReleaseStreams(const std::vector<int32_t>& streamIds) override
    {
        return SUCCESS;
    }

    int32_t CommitStreams(OHOS::HDI::Camera::V1_0::OperationMode mode,
        const std::vector<uint8_t>& modeSetting) override
    {
        return SUCCESS;
    }

    int32_t GetStreamAttributes(std::vector<OHOS::HDI::Camera::V1_0::StreamAttribute>& attributes) override
    {
        return SUCCESS;
    }

    int32_t AttachBufferQueue(int32_t streamId,
        const sptr<OHOS::HDI::Camera::V1_0::BufferProducerSequenceable>& bufferProducer) override
    {
        return SUCCESS;
    }

    int32_t DetachBufferQueue(int32_t streamId) override
    {
        return SUCCESS;
    }

    int32_t Capture(int32_t captureId, const OHOS::HDI::Camera::V1_0::CaptureInfo& info, bool isStreaming) override
    {
        return SUCCESS;
    }

    int32_t CancelCapture(int32_t captureId) override
    {
        if (captureId == 1) {
            return HDI::Camera::V1_2::CAMERA_BUSY;
        }
        return HDI::Camera::V1_2::NO_ERROR;
    }

    int32_t ChangeToOfflineStream(const std::vector<int32_t>& streamIds,
        const sptr<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
            sptr<OHOS::HDI::Camera::V1_0::IOfflineStreamOperator>& offlineOperator) override
    {
        return SUCCESS;
    }

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer)
    {
        majorVer = 1;
        minorVer = 0;
        return HDF_SUCCESS;
    }

    bool IsProxy()
    {
        return false;
    }

    const std::u16string GetDesc()
    {
        return metaDescriptor_;
    }
};

void HStreamCaptureUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamCaptureUnitTest::SetUpTestCase started!");
}

void HStreamCaptureUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamCaptureUnitTest::TearDownTestCase started!");
}

void HStreamCaptureUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("HStreamCaptureUnitTest::SetUp started!");
}

void HStreamCaptureUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("HStreamCaptureUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test SetThumbnail.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetThumbnail with different input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, SetThumbnail001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<OHOS::IBufferProducer> producer1 = nullptr;
    EXPECT_EQ(streamCapture->SetThumbnail(false, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetThumbnail(false, producer), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetThumbnail(true, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetThumbnail(true, producer), CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableRawDelivery.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableRawDelivery with different input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, EnableRawDelivery001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    EXPECT_EQ(streamCapture->EnableRawDelivery(false), CAMERA_OK);
    EXPECT_EQ(streamCapture->EnableRawDelivery(true), CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test SetBufferProducerInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBufferProducerInfo with different input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, SetBufferProducerInfo001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<OHOS::IBufferProducer> producer1 = nullptr;
    std::string bufName = "rawImage";
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer), CAMERA_OK);
    bufName = "gainmapImage";
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer), CAMERA_OK);
    bufName = "deepImage";
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer), CAMERA_OK);
    bufName = "exifImage";
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer), CAMERA_OK);
    bufName = "debugImage";
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetBufferProducerInfo(bufName, producer), CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferImageDeliveryFor.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferImageDeliveryFor with different input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, DeferImageDeliveryFor001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t type = OHOS::HDI::Camera::V1_2::STILL_IMAGE;
    EXPECT_EQ(streamCapture->DeferImageDeliveryFor(type), CAMERA_OK);
    type = OHOS::HDI::Camera::V1_2::MOVING_IMAGE;
    EXPECT_EQ(streamCapture->DeferImageDeliveryFor(type), CAMERA_OK);
    type = OHOS::HDI::Camera::V1_2::MOVING_IMAGE;
    EXPECT_EQ(streamCapture->DeferImageDeliveryFor(type), CAMERA_OK);
    type = OHOS::HDI::Camera::V1_2::NONE;
    EXPECT_EQ(streamCapture->DeferImageDeliveryFor(type), CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test ResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetBurstKey with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, ResetBurstKey001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    auto key = streamCapture->GetBurstKey(captureId);
    EXPECT_EQ(key, "test");
    streamCapture->ResetBurstKey(captureId);
    streamCapture->CheckResetBurstKey(captureId);
    EXPECT_EQ(key, "test");
}

/*
 * Feature: Framework
 * Function: Test ResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetBurstKey with abnormal burstNumMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, ResetBurstKey002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstNumMap_.emplace(0, 0);
    streamCapture->ResetBurstKey(captureId);
    auto key = streamCapture->GetBurstKey(captureId);
    EXPECT_EQ(key, "");
}

/*
 * Feature: Framework
 * Function: Test ResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetBurstKey with abnormal burstImagesMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, ResetBurstKey003, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(0, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    streamCapture->ResetBurstKey(captureId);
    auto ret = streamCapture->GetCurBurstSeq(0);
    EXPECT_EQ(ret, 3);
}

/*
 * Feature: Framework
 * Function: Test ResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetBurstKey with abnormal burstkeyMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, ResetBurstKey004, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(0, "test");
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    streamCapture->ResetBurstKey(captureId);
    auto key = streamCapture->GetBurstKey(0);
    EXPECT_EQ(key, "test");
}

/*
 * Feature: Framework
 * Function: Test GetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBurstKey with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, GetBurstKey001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    auto key = streamCapture->GetBurstKey(captureId);
    EXPECT_EQ(key, "test");
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test GetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBurstKey with abnormal burstkeyMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, GetBurstKey002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_TWO;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    auto key = streamCapture->GetBurstKey(captureId);
    EXPECT_EQ(key, "");
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCurBurstSeq.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCurBurstSeq with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, GetCurBurstSeq001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    auto ret = streamCapture->GetCurBurstSeq(captureId);
    EXPECT_EQ(ret, 3);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCurBurstSeq.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCurBurstSeq with abnormal burstImagesMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, GetCurBurstSeq002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_TWO;
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    auto ret = streamCapture->GetCurBurstSeq(captureId);
    EXPECT_EQ(ret, -1);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test SetBurstImages.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBurstImages with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, SetBurstImages001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    std::string imageId = "image5.jpg";
    std::vector<std::string> images = {"image1.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_TWO, images);
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_THREE, images);
    streamCapture->SetBurstImages(captureId, imageId);
    auto ret = streamCapture->GetCurBurstSeq(HStreamCaptureUnitTest_ONE);
    EXPECT_EQ(ret, 2);
}

/*
 * Feature: Framework
 * Function: Test SetBurstImages.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBurstImages with abnormal burstImagesMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, SetBurstImages002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    std::string imageId = "image4.jpg";
    std::vector<std::string> images = {"image1.jpg", "image2.jpg", "image3.jpg"};
    streamCapture->burstImagesMap_.emplace(0, images);
    streamCapture->SetBurstImages(captureId, imageId);
    auto ret = streamCapture->GetCurBurstSeq(HStreamCaptureUnitTest_ONE);
    EXPECT_EQ(ret, -1);
}

/*
 * Feature: Framework
 * Function: Test CheckResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckResetBurstKey with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckResetBurstKeys001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 0;
    std::string imageId = "image1.jpg";
    std::vector<std::string> images = {"image1.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    streamCapture->CheckResetBurstKey(captureId);
    auto numIter = streamCapture->burstNumMap_.find(captureId);
    EXPECT_NE(numIter != streamCapture->burstNumMap_.end(), true);
}

/*
 * Feature: Framework
 * Function: Test CheckResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckResetBurstKey with abnormal burstImagesMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckResetBurstKeys002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    std::string imageId = "image1.jpg";
    std::vector<std::string> images = {"image1.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_TWO, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_TWO, HStreamCaptureUnitTest_TWO);
    streamCapture->CheckResetBurstKey(captureId);
    auto imageIter = streamCapture->burstImagesMap_.find(captureId);
    EXPECT_EQ(imageIter != streamCapture->burstImagesMap_.end(), true);
}

/*
 * Feature: Framework
 * Function: Test CheckResetBurstKey.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckResetBurstKey with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckResetBurstKeys003, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    std::string imageId = "image1.jpg";
    std::vector<std::string> images = {"image1.jpg"};
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_ONE, images);
    streamCapture->burstImagesMap_.emplace(HStreamCaptureUnitTest_TWO, images);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_ONE, HStreamCaptureUnitTest_ONE);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_TWO, HStreamCaptureUnitTest_ONE);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_THREE, HStreamCaptureUnitTest_ONE);
    streamCapture->burstNumMap_.emplace(HStreamCaptureUnitTest_FOUR, HStreamCaptureUnitTest_FOUR);
    streamCapture->CheckResetBurstKey(captureId);
    auto imageIter = streamCapture->burstImagesMap_.find(captureId);
    EXPECT_EQ(imageIter != streamCapture->burstImagesMap_.end(), true);
    auto numIter = streamCapture->burstNumMap_.find(captureId);
    EXPECT_EQ(numIter != streamCapture->burstNumMap_.end(), true);
}

/*
 * Feature: Framework
 * Function: Test CheckBurstCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckBurstCapture with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckBurstCapture001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    auto cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    int32_t preparedCaptureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    streamCapture->isBursting_ = true;
    auto ret = streamCapture->CheckBurstCapture(metadata, preparedCaptureId);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test CheckBurstCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckBurstCapture with abnormal burstkeyMap_.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckBurstCapture002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    auto cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    int32_t preparedCaptureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "");
    streamCapture->isBursting_ = true;
    auto ret = streamCapture->CheckBurstCapture(metadata, preparedCaptureId);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test CheckBurstCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckBurstCapture with abnormal metadata.
 */
HWTEST_F(HStreamCaptureUnitTest, CheckBurstCapture003, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    auto cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    int32_t preparedCaptureId = HStreamCaptureUnitTest_ONE;
    streamCapture->burstkeyMap_.emplace(0, "");
    streamCapture->isBursting_ = true;
    auto ret = streamCapture->CheckBurstCapture(nullptr, preparedCaptureId);
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureStarted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureStarted with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureStarted001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = 0;
    auto ret = streamCapture->OnCaptureStarted(captureId);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureStarted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureStarted with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureStarted002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 0;
    auto ret = streamCapture->OnCaptureStarted(captureId);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureStarted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureStarted with abnormal captureId.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureStarted003, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 0;
    uint32_t exposureTime = 1000000;
    auto ret = streamCapture->OnCaptureStarted(captureId, exposureTime);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureStarted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureStarted with abnormal captureId.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureStarted004, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = 0;
    uint32_t exposureTime = 1000000;
    auto ret = streamCapture->OnCaptureStarted(captureId, exposureTime);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureEnded.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureEnded with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureEnded001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    int32_t frameCount = HStreamCaptureUnitTest_ONE;
    streamCapture->curCaptureID_ = HStreamCaptureUnitTest_ONE;
    auto ret = streamCapture->OnCaptureEnded(captureId, frameCount);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureEnded.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureEnded with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureEnded002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    int32_t frameCount = HStreamCaptureUnitTest_ONE;
    streamCapture->curCaptureID_ = 0;
    auto ret = streamCapture->OnCaptureEnded(captureId, frameCount);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureError.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureError with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureError001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    int32_t errorCode = BUFFER_LOST;
    streamCapture->curCaptureID_ = HStreamCaptureUnitTest_ONE;
    auto ret = streamCapture->OnCaptureError(captureId, errorCode);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureError.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureError with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureError002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    int32_t errorCode = 0;
    streamCapture->curCaptureID_ = 0;
    auto ret = streamCapture->OnCaptureError(captureId, errorCode);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnFrameShutter.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFrameShutter with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnFrameShutter001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    auto ret = streamCapture->OnFrameShutter(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnFrameShutter.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFrameShutter with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnFrameShutter002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    auto ret = streamCapture->OnFrameShutter(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnFrameShutterEnd.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFrameShutterEnd with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnFrameShutterEnd001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    streamCapture->isBursting_ = true;
    auto ret = streamCapture->OnFrameShutterEnd(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnFrameShutterEnd.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFrameShutterEnd  with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnFrameShutterEnd002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    streamCapture->isBursting_ = false;
    auto ret = streamCapture->OnFrameShutterEnd(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureReady.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureReady with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureReady001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput;
    streamCapture->streamCaptureCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(streamCapture->streamCaptureCallback_, nullptr);
    int32_t captureId = HStreamCaptureUnitTest_ONE;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    streamCapture->isBursting_ = true;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    auto ret = streamCapture->OnCaptureReady(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test OnCaptureReady.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureReady with abnormal streamCaptureCallback_.
 */
HWTEST_F(HStreamCaptureUnitTest, OnCaptureReady002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    int32_t captureId = 0;
    uint64_t timestamp = HStreamCaptureUnitTest_HUNDRED;
    streamCapture->isBursting_ = true;
    streamCapture->burstkeyMap_.emplace(HStreamCaptureUnitTest_ONE, "test");
    auto ret = streamCapture->OnCaptureReady(captureId, timestamp);
    EXPECT_EQ(ret, CAMERA_OK);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test DumpStreamInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpStreamInfo with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, DumpStreamInfo001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    CameraInfoDumper infoDumper(0);
    streamCapture->thumbnailBufferQueue_ = new BufferProducerSequenceable(producer);
    streamCapture->DumpStreamInfo(infoDumper);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test DumpStreamInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpStreamInfo with abnormal thumbnailBufferQueue_.
 */
HWTEST_F(HStreamCaptureUnitTest, DumpStreamInfo002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    CameraInfoDumper infoDumper(0);
    streamCapture->thumbnailBufferQueue_ = nullptr;
    streamCapture->DumpStreamInfo(infoDumper);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test IsDeferredPhotoEnabled.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDeferredPhotoEnabled with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, IsDeferredPhotoEnabled001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->deferredPhotoSwitch_ = HStreamCaptureUnitTest_ONE;
    auto ret = streamCapture->IsDeferredPhotoEnabled();
    EXPECT_EQ(ret, 1);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test IsDeferredPhotoEnabled.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDeferredPhotoEnabled with abnormal deferredPhotoSwitch_.
 */
HWTEST_F(HStreamCaptureUnitTest, IsDeferredPhotoEnabled002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->deferredPhotoSwitch_ = 0;
    auto ret = streamCapture->IsDeferredPhotoEnabled();
    EXPECT_EQ(ret, 0);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test IsDeferredVideoEnabled.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDeferredVideoEnabled with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, IsDeferredVideoEnabled001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->deferredVideoSwitch_ = HStreamCaptureUnitTest_ONE;
    auto ret = streamCapture->IsDeferredVideoEnabled();
    EXPECT_EQ(ret, 1);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test IsDeferredVideoEnabled.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDeferredVideoEnabled with abnormal deferredVideoSwitch_.
 */
HWTEST_F(HStreamCaptureUnitTest, IsDeferredVideoEnabled002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->deferredVideoSwitch_ = 0;
    auto ret = streamCapture->IsDeferredVideoEnabled();
    EXPECT_EQ(ret, 0);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test ConfirmCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConfirmCapture with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, ConfirmCapture001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->streamOperator_ = new IStreamOperatorFork();
    ASSERT_NE(streamCapture->streamOperator_, nullptr);
    streamCapture->isBursting_ = true;
    auto ret = streamCapture->ConfirmCapture();
    EXPECT_EQ(ret, 10);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test ConfirmCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConfirmCapture with abnormal isBursting_.
 */
HWTEST_F(HStreamCaptureUnitTest, ConfirmCapture002, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->streamOperator_ = new IStreamOperatorFork();
    ASSERT_NE(streamCapture->streamOperator_, nullptr);
    streamCapture->isBursting_ = false;
    streamCapture->captureIdForConfirmCapture_ = HStreamCaptureUnitTest_ONE;
    auto ret = streamCapture->ConfirmCapture();
    EXPECT_EQ(ret, 11);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test ConfirmCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConfirmCapture with abnormal captureIdForConfirmCapture_.
 */
HWTEST_F(HStreamCaptureUnitTest, ConfirmCapture003, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    streamCapture->streamOperator_ = new IStreamOperatorFork();
    ASSERT_NE(streamCapture->streamOperator_, nullptr);
    streamCapture->isBursting_ = false;
    streamCapture->captureIdForConfirmCapture_ = 0;
    auto ret = streamCapture->ConfirmCapture();
    EXPECT_EQ(ret, 11);
    streamCapture->Release();
}

/*
 * Feature: Framework
 * Function: Test EndBurstCapture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EndBurstCapture with correct input parameters.
 */
HWTEST_F(HStreamCaptureUnitTest, EndBurstCapture001, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<HStreamCapture> streamCapture = new(std::nothrow) HStreamCapture(producer, format, width, height);
    ASSERT_NE(streamCapture, nullptr);
    auto cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    streamCapture->EndBurstCapture(metadata);
    streamCapture->Release();
}
} // CameraStandard
} // OHOS