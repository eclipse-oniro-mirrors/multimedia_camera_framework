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

#include "camera_photo_proxy_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;
using namespace OHOS::HDI::Camera::V1_1;

void CameraPhotoProxyUnit::SetUpTestCase(void) {}

void CameraPhotoProxyUnit::TearDownTestCase(void) {}

void CameraPhotoProxyUnit::SetUp()
{
    NativeAuthorization();
}

void CameraPhotoProxyUnit::TearDown() {}

void CameraPhotoProxyUnit::NativeAuthorization()
{
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("CameraPhotoProxyUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}


/*
 * Feature: Framework
 * Function: Test CameraPhotoProxy with SetDeferredAttrs and SetLocation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraPhotoProxy with SetDeferredAttrs and SetLocation
 */
HWTEST_F(CameraPhotoProxyUnit, camera_photo_proxy_unittest_001, TestSize.Level0)
{
    std::shared_ptr<CameraPhotoProxy> proxy = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0);
    std::shared_ptr<CameraPhotoProxy> proxy_1 = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0, 0);

    string photoId = "0";
    proxy->SetDeferredAttrs(photoId, 0, 0, 0);
    EXPECT_EQ(proxy->isDeferredPhoto_, 1);

    double latitude = 1;
    double longitude = 1;
    proxy_1->SetLocation(latitude, longitude);
    EXPECT_EQ(proxy_1->longitude_, longitude);
}


/*
 * Feature: Framework
 * Function: Test CameraPhotoProxy with CameraFreeBufferHandle of abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraPhotoProxy with CameraFreeBufferHandle of abnormal branches
 */
HWTEST_F(CameraPhotoProxyUnit, camera_photo_proxy_unittest_002, TestSize.Level0)
{
    std::shared_ptr<CameraPhotoProxy> proxy = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0);

    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = -1;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = -1;
    }
    proxy->bufferHandle_ = handle;
    int32_t ret = proxy->CameraFreeBufferHandle();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test CameraPhotoProxy with CameraFreeBufferHandle of normal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraPhotoProxy with CameraFreeBufferHandle of normal branches
 */
HWTEST_F(CameraPhotoProxyUnit, camera_photo_proxy_unittest_003, TestSize.Level0)
{
    std::shared_ptr<CameraPhotoProxy> proxy = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0);

    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = 0;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = 0;
    }
    proxy->bufferHandle_ = handle;
    int32_t ret = proxy->CameraFreeBufferHandle();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test CameraPhotoProxy with WriteToParcel when bufferHandle is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraPhotoProxy with WriteToParcel when bufferHandle is nullptr
 */
HWTEST_F(CameraPhotoProxyUnit, camera_photo_proxy_unittest_005, TestSize.Level0)
{
    std::shared_ptr<CameraPhotoProxy> proxy = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0);

    proxy->bufferHandle_ = nullptr;
    proxy->format_ = 0;
    MessageParcel parcel;
    proxy->WriteToParcel(parcel);
    proxy->ReadFromParcel(parcel);
    EXPECT_NE(proxy->format_, 16);
}

/*
 * Feature: Framework
 * Function: Test CameraPhotoProxy with WriteToParcel when bufferHandle is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraPhotoProxy with WriteToParcel when bufferHandle is not nullptr
 */
HWTEST_F(CameraPhotoProxyUnit, camera_photo_proxy_unittest_006, TestSize.Level0)
{
    std::shared_ptr<CameraPhotoProxy> proxy = std::make_shared<CameraPhotoProxy>(nullptr, 0, 0, 0, false, 0);

    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = 0;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = 0;
    }
    proxy->bufferHandle_ = handle;
    proxy->format_ = 0;
    MessageParcel parcel;
    proxy->WriteToParcel(parcel);
    proxy->ReadFromParcel(parcel);
    EXPECT_NE(proxy->format_, 16);
}

}
}