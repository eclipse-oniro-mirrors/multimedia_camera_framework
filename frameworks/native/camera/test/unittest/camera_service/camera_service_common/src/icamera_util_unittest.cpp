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

#include "icamera_util_unittest.h"
#include "icamera_util.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_util.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void IcameraUtilUnit::SetUpTestCase(void) {}

void IcameraUtilUnit::TearDownTestCase(void) {}

void IcameraUtilUnit::SetUp() {}

void IcameraUtilUnit::TearDown() {}


/*
 * Feature: Framework
 * Function: Test ServiceToCameraError
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ServiceToCameraError to map various camera error codes to corresponding CameraErrorCode values.
 */
HWTEST_F(IcameraUtilUnit, icamera_util_unittest_001, TestSize.Level0)
{
    int32_t ret = CAMERA_ALLOC_ERROR;
    int32_t err = CameraErrorCode::SERVICE_FATL_ERROR;
    auto result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_UNSUPPORTED;
    err = CameraErrorCode::DEVICE_DISABLED;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_DEVICE_BUSY;
    err = CameraErrorCode::CONFLICT_CAMERA;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_DEVICE_CLOSED;
    err = CameraErrorCode::DEVICE_DISABLED;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_DEVICE_REQUEST_TIMEOUT;
    err = CameraErrorCode::SERVICE_FATL_ERROR;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_STREAM_BUFFER_LOST;
    err = CameraErrorCode::SERVICE_FATL_ERROR;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_CAPTURE_LIMIT_EXCEED;
    err = CameraErrorCode::SERVICE_FATL_ERROR;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_DEVICE_ERROR;
    err = CameraErrorCode::OPERATION_NOT_ALLOWED;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);

    ret = CAMERA_NO_PERMISSION;
    err = CameraErrorCode::OPERATION_NOT_ALLOWED;
    result = ServiceToCameraError(ret);
    EXPECT_EQ(result, err);
}
}
}