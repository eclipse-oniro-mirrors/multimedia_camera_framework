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

#include "camera_utils_unittest.h"

#include "camera_log.h"
#include "capture_scene_const.h"
#include "message_parcel.h"
#include "surface.h"
#include "utils/camera_buffer_handle_utils.h"
#include "utils/camera_report_dfx_uitls.h"
#include "utils/camera_security_utils.h"
#include "utils/dps_metadata_info.h"
#include "utils/metadata_common_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t TEST_INT32_VALUE = 32;
static constexpr int64_t TEST_INT64_VALUE = 64;
static constexpr double TEST_DOUBLE_VALUE = 10.0;
static constexpr char TEST_STRING_VALUE[] = "testValue";
static constexpr int32_t BUFFER_HANDLE_RESERVE_MAX_SIZE = 1024;
static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;

void CameraUtilsUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraUtilsUnitTest::SetUpTestCase started!");
}

void CameraUtilsUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraUtilsUnitTest::TearDownTestCase started!");
}

void CameraUtilsUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraUtilsUnitTest::SetUp started!");
}

void CameraUtilsUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraUtilsUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test the Set/Get/WriteToParcel/ReadFromParcel function of DpsMetadata class.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the Set/Get/WriteToParcel/ReadFromParcel function of DpsMetadata class
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_001, TestSize.Level0)
{
    DpsMetadata metadata;
    std::string int32Key = "int32_t";
    std::string int64Key = "int64_t";
    std::string doubleKey = "double";
    std::string stringKey = "string";
    metadata.Set(int32Key, TEST_INT32_VALUE);
    metadata.Set(int64Key, TEST_INT64_VALUE);
    metadata.Set(doubleKey, TEST_DOUBLE_VALUE);
    metadata.Set(stringKey, TEST_STRING_VALUE);
    MessageParcel parcel;
    DpsMetadataError ret = metadata.WriteToParcel(parcel);
    EXPECT_EQ(ret, DPS_METADATA_OK);

    metadata.ReadFromParcel(parcel);
    int32_t int32Value;
    int64_t int64Value;
    double doubleValue;
    std::string stringValue;
    metadata.Get(int32Key, int32Value);
    EXPECT_EQ(int32Value, TEST_INT32_VALUE);
    metadata.Get(int64Key, int64Value);
    EXPECT_EQ(int64Value, TEST_INT64_VALUE);
    metadata.Get(doubleKey, doubleValue);
    EXPECT_EQ(doubleValue, TEST_DOUBLE_VALUE);
    metadata.Get(stringKey, stringValue);
    EXPECT_EQ(stringValue, TEST_STRING_VALUE);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function when camera support stream available basic configurations.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the GetSupportedPreviewSizeRange function camera support stream available basic configurations.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_002, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 };

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::CAPTURE,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    ASSERT_NE(sizeList->size(), 0);
    auto size = *sizeList.get();
    EXPECT_EQ(size[0].width, 640);
    EXPECT_EQ(size[0].height, 480);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function when camera available profile level with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera available profile level with CAPTURE mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_003, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::CAPTURE,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function when camera available profile level with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera available profile level with VIDEO mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_004, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::VIDEO,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function when camera available profile level with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera available profile level with NIGHT mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_005, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::NIGHT,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPreviewSizeRange when camera support extend configurations with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera support extend configurations with CAPTURE mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_006, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::CAPTURE,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPreviewSizeRange when camera support extend configurations with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera support extend configurations with VIDEO mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_007, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::VIDEO,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function
 * when camera support extend configurations with empty stream info.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPreviewSizeRange when camera support extend configurations with NIGHT mode.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_008, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = {0};

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::NIGHT,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the GetSupportedPreviewSizeRange function when metadata is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the GetSupportedPreviewSizeRange function when when metadata is nullptr.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_009, TestSize.Level0)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(SceneMode::CAPTURE,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, metadata);
    ASSERT_NE(sizeList, nullptr);
    EXPECT_EQ(sizeList->size(), 0);
}

/*
 * Feature: Framework
 * Function: Test CameraCloneBufferHandle when param is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraCloneBufferHandle when param is nullptr.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_010, TestSize.Level0)
{
    BufferHandle *testBufferHandle = CameraCloneBufferHandle(nullptr);
    EXPECT_EQ(testBufferHandle, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraCloneBufferHandle when reserveFds and reserveInts is out of range.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraCloneBufferHandle when reserveFds and reserveInts is out of range.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_011, TestSize.Level0)
{
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(sizeof(BufferHandle)));
    handle->reserveFds = BUFFER_HANDLE_RESERVE_MAX_SIZE + 1;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_MAX_SIZE + 1;
    BufferHandle *testBufferHandle = CameraCloneBufferHandle(handle);
    EXPECT_EQ(testBufferHandle, nullptr);
    free(handle);
}

/*
 * Feature: Framework
 * Function: Test CameraCloneBufferHandle when reserveInts is 0.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraCloneBufferHandle when reserveInts is 0.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_012, TestSize.Level0)
{
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = -1;
    handle->width = 640;
    handle->height = 480;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = 0;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE; i++) {
        handle->reserve[i] = 0;
    }
    BufferHandle *testBufferHandle = CameraCloneBufferHandle(handle);
    EXPECT_EQ(testBufferHandle->width, 640);
    EXPECT_EQ(testBufferHandle->height, 480);
    free(handle);
}

/*
 * Feature: Framework
 * Function: Test CameraCloneBufferHandle when reserveInts is not 0.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraCloneBufferHandle when reserveInts is not 0.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_013, TestSize.Level0)
{
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = -1;
    handle->width = 640;
    handle->height = 480;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = 0;
    }
    BufferHandle *testBufferHandle = CameraCloneBufferHandle(handle);
    EXPECT_EQ(testBufferHandle->width, 640);
    EXPECT_EQ(testBufferHandle->height, 480);
    free(handle);
}

/*
 * Feature: Framework
 * Function: Test CameraFreeBufferHandle when param is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraFreeBufferHandle when param is nullptr.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_014, TestSize.Level0)
{
    int32_t ret = CameraFreeBufferHandle(nullptr);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test CameraFreeBufferHandle when param is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraFreeBufferHandle when param is nullptr.
 */
HWTEST_F(CameraUtilsUnitTest, camera_utils_unittest_015, TestSize.Level0)
{
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    handle->fd = -1;
    handle->reserveFds = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    handle->reserveInts = BUFFER_HANDLE_RESERVE_TEST_SIZE;
    for (uint32_t i = 0; i < BUFFER_HANDLE_RESERVE_TEST_SIZE * 2; i++) {
        handle->reserve[i] = 0;
    }
    int32_t ret = CameraFreeBufferHandle(handle);
    EXPECT_EQ(ret, 0);
}
} // CameraStandard
} // OHOS
