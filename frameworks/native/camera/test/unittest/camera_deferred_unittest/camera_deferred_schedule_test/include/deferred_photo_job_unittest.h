/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef DEFERRED_PHOTO_JOB_UNITTEST_H
#define DEFERRED_PHOTO_JOB_UNITTEST_H

#include "dps_metadata_info.h"
#include "gtest/gtest.h"
#include "photo_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class DeferredPhotoJobUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    std::unique_ptr<PhotoJobQueue> jobQueue_ {nullptr};
};

class TestPhotoJob {
public:
    TestPhotoJob(std::string imageId, DeferredProcessingType type)
    {
        imageId_ = imageId;
        type_ = type;
        metadata_.Set(DEFERRED_PROCESSING_TYPE_KEY, type);
    };
    ~TestPhotoJob() = default;

    std::string imageId_;
    DpsMetadata metadata_;
    DeferredProcessingType type_;
};
} // DeferredProcessing
} // CameraStandard
} // OHOS
#endif // DEFERRED_PHOTO_JOB_UNITTEST_H
