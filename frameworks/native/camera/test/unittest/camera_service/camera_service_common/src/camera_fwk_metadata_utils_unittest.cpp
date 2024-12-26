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

#include "camera_fwk_metadata_utils_unittest.h"

#include "camera_device.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_fwk_metadata_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraFwkMetadataUtilsUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraFwkMetadataUtilsUnitTest::SetUpTestCase started!");
}

void CameraFwkMetadataUtilsUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraFwkMetadataUtilsUnitTest::TearDownTestCase started!");
}

void CameraFwkMetadataUtilsUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraFwkMetadataUtilsUnitTest::SetUp started!");
}

void CameraFwkMetadataUtilsUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraFwkMetadataUtilsUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test DumpMetadataInfo normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpMetadataInfo normal branch.
 */
HWTEST_F(CameraFwkMetadataUtilsUnitTest, camera_fwk_metadata_utils_unittest_001, TestSize.Level0)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<int32_t> testStreamInfo = { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 };

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount,
        dataSize);
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    CameraFwkMetadataUtils::DumpMetadataInfo(metadata);
    ASSERT_NE(metadata, nullptr);
}

/*
 * Feature: Framework
 * Function: Test DumpMetadataItemInfo and RecreateMetadata normal branch with different dataType.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpMetadataItemInfo and RecreateMetadata normal branch with different dataType.
 */
HWTEST_F(CameraFwkMetadataUtilsUnitTest, camera_fwk_metadata_utils_unittest_002, TestSize.Level0)
{
    camera_metadata_item_t item;
    item.data_type = META_TYPE_BYTE;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_INT32;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_UINT32;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_FLOAT;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_INT64;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_DOUBLE;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    item.data_type = META_TYPE_RATIONAL;
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> testMetadata =
        CameraFwkMetadataUtils::RecreateMetadata(metadata);
    ASSERT_NE(testMetadata, nullptr);

    bool ret = CameraFwkMetadataUtils::MergeMetadata(metadata, testMetadata);
    EXPECT_TRUE(ret);
}

/*
 * Feature: Framework
 * Function: Test UpdateMetadataTag normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateMetadataTag normal branch.
 */
HWTEST_F(CameraFwkMetadataUtilsUnitTest, camera_fwk_metadata_utils_unittest_003, TestSize.Level0)
{
    camera_metadata_item_t item;
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    bool ret = CameraFwkMetadataUtils::UpdateMetadataTag(item, dstMetadata);
    EXPECT_FALSE(ret);
}
} // CameraStandard
} // OHOS
