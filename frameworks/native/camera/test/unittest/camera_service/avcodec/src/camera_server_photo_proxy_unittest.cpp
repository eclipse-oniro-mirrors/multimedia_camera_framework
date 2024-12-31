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
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_001, TestSize.Level0)
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
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_002, TestSize.Level0)
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
HWTEST_F(CameraServerPhotoProxyUnitTest, camera_server_photo_proxy_unittest_003, TestSize.Level0)
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
} // CameraStandard
} // OHOS
