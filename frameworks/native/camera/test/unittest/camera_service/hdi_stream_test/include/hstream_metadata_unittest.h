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

#ifndef HSTREAM_METADATA_UNITTEST_H
#define HSTREAM_METADATA_UNITTEST_H

#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "hstream_metadata.h"

namespace OHOS {
namespace CameraStandard {
class TestHStreamMetadataStub : public HStreamMetadataStub {
public:
    int32_t Start() {return 0;};
    virtual int32_t Stop() {return 0;};
    virtual int32_t Release() {return 0;};
    virtual int32_t SetCallback(sptr<IStreamMetadataCallback>& callback) {return 0;};
    virtual int32_t UnSetCallback() {return 0;};
    virtual int32_t EnableMetadataType(std::vector<int32_t> metadataTypes) {return 0;};
    virtual int32_t DisableMetadataType(std::vector<int32_t> metadataTypes) {return 0;};
    virtual int32_t OperatePermissionCheck(uint32_t interfaceCode) {return 0;};
};

class HStreamMetadataUnit : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp(void);

    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);
};
} // CameraStandard
} // OHOS
#endif