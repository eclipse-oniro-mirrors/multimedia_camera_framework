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
#include "hstream_metadata_unittest.h"
#include "camera_service_ipc_interface_code.h"
#include "test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void HStreamMetadataUnitTest::SetUpTestCase(void) {}

void HStreamMetadataUnitTest::TearDownTestCase(void) {}

void HStreamMetadataUnitTest::TearDown(void) {}

void HStreamMetadataUnitTest::SetUp(void) {}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OperatePermissionCheck for an unauthorized caller token when starting a stream metadata operation.
 *    The expected return value is CAMERA_OPERATION_NOT_ALLOWED.
 */
HWTEST_F(HStreamMetadataUnitTest, hstream_metadata_unittest_001, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, format, {1});
    ASSERT_NE(streamMetadata, nullptr);
    uint32_t interfaceCode = CAMERA_STREAM_META_START;
    streamMetadata->callerToken_ = 110;
    int32_t ret = streamMetadata->OperatePermissionCheck(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);

}
} // CameraStandard
} // OHOS
