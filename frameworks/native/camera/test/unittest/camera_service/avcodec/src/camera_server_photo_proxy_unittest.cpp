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

#include "camera_server_photo_proxy_unittest.h"

#include "avcodec_task_manager.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;

void CameraServerPhotoProxyUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxyUnitTest::SetUpTestCase started!");
}

void CameraServerPhotoProxyUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxyUnitTest::TearDownTestCase started!");
}

void CameraServerPhotoProxyUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxyUnitTest::SetUp started!");
}

void CameraServerPhotoProxyUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxyUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetFormat normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFormat normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_001, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    cameraPhotoProxy->bufferHandle_ = static_cast<BufferHandle *>(malloc(handleSize));
    cameraPhotoProxy->imageFormat_ = 2;
    cameraPhotoProxy->isMmaped_ = true;
    cameraPhotoProxy->GetFileDataAddr();
    Media::PhotoFormat format = cameraPhotoProxy->GetFormat();
    EXPECT_EQ(format, Media::PhotoFormat::HEIF);

    cameraPhotoProxy->imageFormat_ = 10;
    cameraPhotoProxy->isMmaped_ = false;
    cameraPhotoProxy->GetFileDataAddr();
    format = cameraPhotoProxy->GetFormat();
    EXPECT_EQ(format, Media::PhotoFormat::RGBA);
    free(cameraPhotoProxy->bufferHandle_);
    cameraPhotoProxy->bufferHandle_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test GetDeferredProcType normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetDeferredProcType normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_002, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->deferredProcType_ = 0;
    Media::DeferredProcType type = cameraPhotoProxy->GetDeferredProcType();
    EXPECT_EQ(type, Media::DeferredProcType::BACKGROUND);

    cameraPhotoProxy->deferredProcType_ = 1;
    type = cameraPhotoProxy->GetDeferredProcType();
    EXPECT_EQ(type, Media::DeferredProcType::OFFLINE);
}

/*
 * Feature: Framework
 * Function: Test GetShootingMode normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetShootingMode normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_003, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->mode_ = 100;
    cameraPhotoProxy->isMmaped_ = false;
    cameraPhotoProxy->bufferHandle_ = nullptr;
    int32_t ret = cameraPhotoProxy->GetShootingMode();
    EXPECT_EQ(ret, 0);

    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    cameraPhotoProxy->bufferHandle_ = static_cast<BufferHandle *>(malloc(handleSize));

    cameraPhotoProxy->mode_ = 2;
    ret = cameraPhotoProxy->GetShootingMode();
    EXPECT_EQ(ret, 0);
    free(cameraPhotoProxy->bufferHandle_);
    cameraPhotoProxy->bufferHandle_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test GetWidth normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetWidth normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_004, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->photoWidth_ = 1;
    int32_t ret = cameraPhotoProxy->GetWidth();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test GetHeight normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetHeight normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_005, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->photoHeight_ = 1;
    int32_t ret = cameraPhotoProxy->GetHeight();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test GetCaptureId normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCaptureId normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_006, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->captureId_ = 1;
    int32_t ret = cameraPhotoProxy->GetCaptureId();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test GetBurstSeqId normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBurstSeqId normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_007, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->burstSeqId_ = 1;
    int32_t ret = cameraPhotoProxy->GetBurstSeqId();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test GetPhotoId normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPhotoId normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_008, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->photoId_ = "1";
    std::string ret = cameraPhotoProxy->GetPhotoId();
    EXPECT_EQ(ret, "1");
}

/*
 * Feature: Framework
 * Function: Test GetPhotoId normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPhotoId normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_009, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->photoId_ = "123";
    std::string ret = cameraPhotoProxy->GetPhotoId();
    EXPECT_EQ(ret, "123");
}

/*
 * Feature: Framework
 * Function: Test GetFileSize normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFileSize normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_010, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->fileSize_ = 1;
    size_t ret = cameraPhotoProxy->GetFileSize();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test GetPhotoQuality normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPhotoQuality normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_011, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->isHighQuality_ = true;
    EXPECT_EQ(cameraPhotoProxy->GetPhotoQuality(), Media::PhotoQuality::HIGH);

    cameraPhotoProxy->isHighQuality_ = false;
    EXPECT_EQ(cameraPhotoProxy->GetPhotoQuality(), Media::PhotoQuality::LOW);
}

/*
 * Feature: Framework
 * Function: Test GetTitle normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTitle normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_012, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->SetDisplayName("123");
    std::string ret = cameraPhotoProxy->GetTitle();
    EXPECT_EQ(ret, "123");
}

/*
 * Feature: Framework
 * Function: Test GetLatitude normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetLatitude normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_013, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->latitude_ = 0.5;
    double ret = cameraPhotoProxy->GetLatitude();
    EXPECT_EQ(ret, 0.5);
}

/*
 * Feature: Framework
 * Function: Test GetLongitude normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetLongitude normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_014, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->longitude_ = 0.5;
    double ret = cameraPhotoProxy->GetLongitude();
    EXPECT_EQ(ret, 0.5);
}

/*
 * Feature: Framework
 * Function: Test GetShootingMode normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetShootingMode normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_015, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->SetShootingMode(0);
    int32_t ret = cameraPhotoProxy->GetShootingMode();
    EXPECT_EQ(ret, 0);

    cameraPhotoProxy->SetShootingMode(3);
    ret = cameraPhotoProxy->GetShootingMode();
    EXPECT_EQ(ret, 23);
}

/*
 * Feature: Framework
 * Function: Test GetBurstKey normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBurstKey normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_016, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->burstKey_ = "123";
    std::string ret = cameraPhotoProxy->GetBurstKey();
    EXPECT_EQ(ret, "123");
}

/*
 * Feature: Framework
 * Function: Test IsCoverPhoto normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsCoverPhoto normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_017, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->isCoverPhoto_ = true;
    bool ret = cameraPhotoProxy->IsCoverPhoto();
    EXPECT_EQ(ret, true);

    cameraPhotoProxy->isCoverPhoto_ = false;
    ret = cameraPhotoProxy->IsCoverPhoto();
    EXPECT_EQ(ret, false);
}

/*
 * Feature: Framework
 * Function: Test SetBurstInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBurstInfo
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_018, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->SetBurstInfo("123", true);
    EXPECT_EQ(cameraPhotoProxy->GetBurstKey(), "123");
    EXPECT_EQ(cameraPhotoProxy->IsCoverPhoto(), true);
    EXPECT_EQ(cameraPhotoProxy->GetPhotoQuality(), Media::PhotoQuality::HIGH);

    cameraPhotoProxy->SetBurstInfo("123", false);
    EXPECT_EQ(cameraPhotoProxy->GetBurstKey(), "123");
    EXPECT_EQ(cameraPhotoProxy->IsCoverPhoto(), false);
    EXPECT_EQ(cameraPhotoProxy->GetPhotoQuality(), Media::PhotoQuality::HIGH);
}

/*
 * Feature: Framework
 * Function: Test GetCloudImageEnhanceFlag normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCloudImageEnhanceFlag normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_019, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->cloudImageEnhanceFlag_ = 0;
    uint32_t ret = cameraPhotoProxy->GetCloudImageEnhanceFlag();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test GetExtension normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExtension normal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_020, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->imageFormat_ = 2;
    Media::PhotoFormat format = cameraPhotoProxy->GetFormat();
    EXPECT_EQ(format, Media::PhotoFormat::HEIF);
    std::string suffix = cameraPhotoProxy->GetExtension();
    EXPECT_EQ(suffix, suffixHeif);

    cameraPhotoProxy->imageFormat_ = 4;
    format = cameraPhotoProxy->GetFormat();
    EXPECT_EQ(format, Media::PhotoFormat::DNG);
    suffix = cameraPhotoProxy->GetExtension();
    EXPECT_EQ(suffix, suffixDng);

    cameraPhotoProxy->imageFormat_ = 10;
    format = cameraPhotoProxy->GetFormat();
    EXPECT_EQ(format, Media::PhotoFormat::RGBA);
    suffix = cameraPhotoProxy->GetExtension();
    EXPECT_EQ(suffix, suffixJpeg);
}

/*
 * Feature: Framework
 * Function: Test GetFileDataAddr abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFileDataAddr abnormal branches.
 */
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_021, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->bufferHandle_ = nullptr;
    cameraPhotoProxy->fileDataAddr_ = nullptr;
    EXPECT_EQ(cameraPhotoProxy->GetFileDataAddr(), nullptr);

    cameraPhotoProxy->isMmaped_ = false;
    cameraPhotoProxy->Release();
    cameraPhotoProxy->isMmaped_ = true;
    cameraPhotoProxy->Release();
}

} // CameraStandard
} // OHOS
