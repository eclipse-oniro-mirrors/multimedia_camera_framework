/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef VIDEO_ENCODER_UNITTEST_H
#define VIDEO_ENCODER_UNITTEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "message_parcel.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {

class VideoEncoderUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();
};

class MockCodecSurface : public Surface {
public:
    bool IsConsumer() const override
    {
        return false;
    }
    sptr<IBufferProducer> GetProducer() const override
    {
        return nullptr;
    }
    GSError AttachBuffer(sptr<SurfaceBuffer> &buffer) override
    {
        (void)buffer;
        return GSERROR_NOT_SUPPORT;
    }
    GSError DetachBuffer(sptr<SurfaceBuffer> &buffer) override
    {
        (void)buffer;
        return GSERROR_NOT_SUPPORT;
    }
    uint32_t GetQueueSize() override
    {
        return 0;
    }
    GSError SetQueueSize(uint32_t queueSize) override
    {
        (void)queueSize;
        return GSERROR_NOT_SUPPORT;
    }
    int32_t GetDefaultWidth() override
    {
        return 0;
    }
    int32_t GetDefaultHeight() override
    {
        return 0;
    }
    GSError SetDefaultUsage(uint64_t usage) override
    {
        (void)usage;
        return GSERROR_NOT_SUPPORT;
    }
    uint64_t GetDefaultUsage() override
    {
        return 0;
    }
    GSError SetUserData(const std::string &key, const std::string &val) override
    {
        (void)key;
        (void)val;
        return GSERROR_NOT_SUPPORT;
    }
    std::string GetUserData(const std::string &key) override
    {
        (void)key;
        return std::string("");
    }
    const std::string &GetName() override
    {
        return name_;
    }
    uint64_t GetUniqueId() const override
    {
        return 0;
    }
    GSError GoBackground() override
    {
        return GSERROR_NOT_SUPPORT;
    }
    GSError SetTransform(GraphicTransformType transform) override
    {
        (void)transform;
        return GSERROR_NOT_SUPPORT;
    }
    GraphicTransformType GetTransform() const override
    {
        return GRAPHIC_ROTATE_NONE;
    }
    GSError SetScalingMode(uint32_t sequence, ScalingMode scalingMode) override
    {
        (void)sequence;
        (void)scalingMode;
        return GSERROR_NOT_SUPPORT;
    }
    GSError SetMetaData(uint32_t sequence, const std::vector<GraphicHDRMetaData> &metaData) override
    {
        (void)sequence;
        (void)metaData;
        return GSERROR_NOT_SUPPORT;
    }
    GSError SetMetaDataSet(uint32_t sequence, GraphicHDRMetadataKey key, const std::vector<uint8_t> &metaData) override
    {
        (void)sequence;
        (void)key;
        (void)metaData;
        return GSERROR_NOT_SUPPORT;
    }
    GSError SetTunnelHandle(const GraphicExtDataHandle *handle) override
    {
        (void)handle;
        return GSERROR_NOT_SUPPORT;
    }
    void Dump(std::string &result) const override
    {
        (void)result;
    }
    GSError AttachBuffer(sptr<SurfaceBuffer> &buffer, int32_t timeOut) override
    {
        (void)buffer;
        (void)timeOut;
        return GSERROR_NOT_SUPPORT;
    }
    GSError RegisterSurfaceDelegator(sptr<IRemoteObject> client) override
    {
        (void)client;
        return GSERROR_NOT_SUPPORT;
    }
    GSError RegisterReleaseListener(OnReleaseFuncWithFence func) override
    {
        (void)func;
        return GSERROR_NOT_SUPPORT;
    }
    GSError RegisterUserDataChangeListener(const std::string &funcName, OnUserDataChangeFunc func) override
    {
        (void)funcName;
        (void)func;
        return GSERROR_NOT_SUPPORT;
    }
    GSError UnRegisterUserDataChangeListener(const std::string &funcName) override
    {
        (void)funcName;
        return GSERROR_NOT_SUPPORT;
    }
    GSError ClearUserDataChangeListener() override
    {
        return GSERROR_NOT_SUPPORT;
    }
    GSError AttachBufferToQueue(sptr<SurfaceBuffer> buffer) override
    {
        (void)buffer;
        return GSERROR_NOT_SUPPORT;
    }
    GSError DetachBufferFromQueue(sptr<SurfaceBuffer> buffer, bool isReserveSlot = false) override
    {
        (void)buffer;
        return GSERROR_NOT_SUPPORT;
    }
    GraphicTransformType GetTransformHint() const override
    {
        return GRAPHIC_ROTATE_NONE;
    }
    GSError SetTransformHint(GraphicTransformType transformHint) override
    {
        (void)transformHint;
        return GSERROR_NOT_SUPPORT;
    }
    void SetBufferHold(bool hold) override
    {
        (void)hold;
    }
    GSError SetScalingMode(ScalingMode scalingMode) override
    {
        (void)scalingMode;
        return GSERROR_NOT_SUPPORT;
    }
    GSError SetSurfaceSourceType(OHSurfaceSource sourceType) override
    {
        (void)sourceType;
        return GSERROR_NOT_SUPPORT;
    }
    OHSurfaceSource GetSurfaceSourceType() const override
    {
        return OH_SURFACE_SOURCE_DEFAULT;
    }
    GSError SetSurfaceAppFrameworkType(std::string appFrameworkType) override
    {
        (void)appFrameworkType;
        return GSERROR_NOT_SUPPORT;
    }
    std::string GetSurfaceAppFrameworkType() const override
    {
        return std::string("");
    }

private:
    const std::string name_ = "";
};

} // CameraStandard
} // OHOS
#endif // VIDEO_ENCODER_UNITTEST_H