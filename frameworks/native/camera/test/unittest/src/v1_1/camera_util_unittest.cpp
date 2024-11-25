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

#include "camera_util_unittest.h"

#include "camera_log.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

using namespace OHOS::HDI::Camera::V1_0;

void CameraUtilUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraUtilUnitTest::SetUpTestCase started!");
}

void CameraUtilUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraUtilUnitTest::TearDownTestCase started!");
}

void CameraUtilUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraUtilUnitTest::SetUp started!");
}

void CameraUtilUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraUtilUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test HdiToServiceError normal branches with different parameters.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HdiToServiceError normal branches with different parameters.
 */
HWTEST_F(CameraUtilUnitTest, camera_util_unittest_001, TestSize.Level0)
{
    OHOS::HDI::Camera::V1_0::CamRetCode testRet = OHOS::HDI::Camera::V1_0::NO_ERROR;
    int32_t ret = HdiToServiceError(testRet);
    EXPECT_EQ(ret, CAMERA_OK);

    testRet = OHOS::HDI::Camera::V1_0::CAMERA_BUSY;
    ret = HdiToServiceError(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_BUSY);
    
    testRet = OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    ret = HdiToServiceError(testRet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);

    testRet = OHOS::HDI::Camera::V1_0::CAMERA_CLOSED;
    ret = HdiToServiceError(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_CLOSED);

    testRet = OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    ret = HdiToServiceError(testRet);
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test HdiToCameraErrorType normal branches with different parameters.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HdiToCameraErrorType normal branches with different parameters.
 */
HWTEST_F(CameraUtilUnitTest, camera_util_unittest_002, TestSize.Level0)
{
    OHOS::HDI::Camera::V1_3::ErrorType type = OHOS::HDI::Camera::V1_3::FATAL_ERROR;
    int32_t ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_FATAL_ERROR);

    type = OHOS::HDI::Camera::V1_3::REQUEST_TIMEOUT;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_REQUEST_TIMEOUT);

    type = OHOS::HDI::Camera::V1_3::DRIVER_ERROR;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_DRIVER_ERROR);

    type = OHOS::HDI::Camera::V1_3::DEVICE_PREEMPT;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_PREEMPTED);

    type = OHOS::HDI::Camera::V1_3::DEVICE_DISCONNECT;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_DISCONNECT);

    type = OHOS::HDI::Camera::V1_3::SENSOR_DATA_ERROR;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DEVICE_SENSOR_DATA_ERROR);

    type = OHOS::HDI::Camera::V1_3::DCAMERA_ERROR_BEGIN;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DCAMERA_ERROR_BEGIN);

    type = OHOS::HDI::Camera::V1_3::DCAMERA_ERROR_DEVICE_IN_USE;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DCAMERA_ERROR_DEVICE_IN_USE);

    type = OHOS::HDI::Camera::V1_3::DCAMERA_ERROR_NO_PERMISSION;
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_DCAMERA_ERROR_NO_PERMISSION);

    int32_t testRet = 6;
    type = static_cast<OHOS::HDI::Camera::V1_3::ErrorType>(testRet);
    ret = HdiToCameraErrorType(type);
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test HdiToServiceErrorV1_2 normal branches with different parameters.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HdiToServiceErrorV1_2 normal branches with different parameters.
 */
HWTEST_F(CameraUtilUnitTest, camera_util_unittest_003, TestSize.Level0)
{
    OHOS::HDI::Camera::V1_2::CamRetCode testRet = OHOS::HDI::Camera::V1_2::NO_ERROR;
    int32_t ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_OK);

    testRet = OHOS::HDI::Camera::V1_2::CAMERA_BUSY;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_BUSY);
    
    testRet = OHOS::HDI::Camera::V1_2::INVALID_ARGUMENT;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);

    testRet = OHOS::HDI::Camera::V1_2::CAMERA_CLOSED;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_CLOSED);

    testRet = OHOS::HDI::Camera::V1_2::DEVICE_ERROR;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_ERROR);

    testRet = OHOS::HDI::Camera::V1_2::NO_PERMISSION;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_NO_PERMISSION);

    testRet = OHOS::HDI::Camera::V1_2::DEVICE_CONFLICT;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_DEVICE_CONFLICT);

    testRet = OHOS::HDI::Camera::V1_2::INSUFFICIENT_RESOURCES;
    ret = HdiToServiceErrorV1_2(testRet);
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test JudgmentPriority and IsSameClient function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test JudgmentPriority and IsSameClient function.
 */
HWTEST_F(CameraUtilUnitTest, camera_util_unittest_004, TestSize.Level0)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    int32_t ret = JudgmentPriority(pid, pid);
    EXPECT_EQ(ret, 0);
    bool boolRet = IsSameClient(pid, pid);
    EXPECT_TRUE(boolRet);
}

/*
 * Feature: Framework
 * Function: Test GetStreamRotation normal branches with different parameters.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetStreamRotation normal branches with different parameters.
 */
HWTEST_F(CameraUtilUnitTest, camera_util_unittest_005, TestSize.Level0)
{
    int32_t sensorOrientation = DISPALY_ROTATE_0;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    int disPlayRotation = 1;
    std::string deviceClass = "phone";
    int32_t ret = GetStreamRotation(sensorOrientation, cameraPosition, disPlayRotation, deviceClass);
    EXPECT_EQ(ret, 270);

    sensorOrientation = DISPALY_ROTATE_1;
    ret = GetStreamRotation(sensorOrientation, cameraPosition, disPlayRotation, deviceClass);
    EXPECT_EQ(ret, 269);

    sensorOrientation = DISPALY_ROTATE_2;
    ret = GetStreamRotation(sensorOrientation, cameraPosition, disPlayRotation, deviceClass);
    EXPECT_EQ(ret, 268);

    sensorOrientation = DISPALY_ROTATE_3;
    ret = GetStreamRotation(sensorOrientation, cameraPosition, disPlayRotation, deviceClass);
    EXPECT_EQ(ret, 267);

    cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    ret = GetStreamRotation(sensorOrientation, cameraPosition, disPlayRotation, deviceClass);
    EXPECT_EQ(ret, 273);
}
} // CameraStandard
} // OHOS
