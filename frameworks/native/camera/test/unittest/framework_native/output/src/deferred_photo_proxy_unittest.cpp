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

#include "deferred_photo_proxy_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "test_token.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {

static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;
using namespace OHOS::HDI::Camera::V1_1;

void DeferredPhotoProxyUnit::SetUpTestCase(void) {}

void DeferredPhotoProxyUnit::TearDownTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void DeferredPhotoProxyUnit::SetUp() {}

void DeferredPhotoProxyUnit::TearDown() {}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy when destruction and isMmaped is false
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_001, TestSize.Level1)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy when destruction and isMmaped is true
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_002, TestSize.Level1)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->isMmaped_ = true;
    proxy->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when GetDeferredProcType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with GetDeferredProcType when deferredProcType_ is 0 or 1
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_003, TestSize.Level1)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    Media::DeferredProcType ret = proxy->GetDeferredProcType();
    EXPECT_EQ(ret, Media::DeferredProcType::BACKGROUND);

    proxy->deferredProcType_ = 1;
    ret = proxy->GetDeferredProcType();
    EXPECT_EQ(ret, Media::DeferredProcType::OFFLINE);
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when GetFileDataAddr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with GetFileDataAddr when isMmaped_ is true
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_004, TestSize.Level1)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->isMmaped_ = true;
    void* ret = proxy->GetFileDataAddr();
    EXPECT_EQ(ret, proxy->fileDataAddr_);
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when different construction parameters and Some Get interfaces
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy when different construction parameters and Some Get interfaces
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_005, TestSize.Level1)
{
    std::string imageId = "0";
    std::vector<uint8_t> data;
    data.push_back(0);
    std::shared_ptr<DeferredPhotoProxy> proxy_1 = std::make_shared<DeferredPhotoProxy>(nullptr, imageId, 0);
    ASSERT_NE(proxy_1, nullptr);

    std::string photoId = "1";
    proxy_1->photoId_ = photoId;
    std::string ret = proxy_1->GetPhotoId();
    EXPECT_EQ(ret, photoId);
    EXPECT_EQ(proxy_1->GetFormat(), Media::PhotoFormat::RGBA);
    EXPECT_EQ(proxy_1->GetPhotoQuality(), Media::PhotoQuality::LOW);


    proxy_1->buffer_ = data.data();
    proxy_1->fileSize_ = 0;
    EXPECT_EQ(proxy_1->GetFileSize(), 0);

    proxy_1->photoWidth_ = 0;
    proxy_1->photoHeight_ = 0;
    EXPECT_EQ(proxy_1->GetWidth(), 0);
    EXPECT_EQ(proxy_1->GetHeight(), 0);
    EXPECT_EQ(proxy_1->GetTitle(), "");
    EXPECT_EQ(proxy_1->GetExtension(), "");
    EXPECT_EQ(proxy_1->GetLatitude(), 0);
    EXPECT_EQ(proxy_1->GetLongitude(), 0);
    EXPECT_EQ(proxy_1->GetBurstKey(), "");
    EXPECT_FALSE(proxy_1->IsCoverPhoto());
    EXPECT_EQ(proxy_1->GetShootingMode(), 0);

    proxy_1->buffer_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy with WriteToParcel and ReadFromParcel
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with WriteToParcel and ReadFromParcel
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_006, TestSize.Level1)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->photoId_ = "";
    proxy->deferredProcType_ = 0;
    proxy->photoWidth_ = 0;
    proxy->photoHeight_ = 0;
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = -1;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = 0;
    }
    proxy->bufferHandle_ = handle;
    MessageParcel parcel;
    proxy->WriteToParcel(parcel);
    proxy->ReadFromParcel(parcel);
    EXPECT_EQ(parcel.ReadString().size(), 0);

    proxy->bufferHandle_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy with Different construction parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with Different construction parameters
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_007, TestSize.Level1)
{
    std::string imageId = "0";
    std::shared_ptr<DeferredPhotoProxy> proxy = std::make_shared<DeferredPhotoProxy>(nullptr, imageId,
        0, nullptr, 0);
    ASSERT_NE(proxy, nullptr);

    proxy->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy with Different construction parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with Different construction parameters
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_008, TestSize.Level1)
{
    std::string imageId = "0";
    std::shared_ptr<DeferredPhotoProxy> proxy = std::make_shared<DeferredPhotoProxy>(nullptr, imageId, 0, 0, 0);
    ASSERT_NE(proxy, nullptr);

    proxy->Release();
}
}
}