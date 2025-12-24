/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DEFERREDPROCESSING_FUZZER_H
#define DEFERREDPROCESSING_FUZZER_H
#define FUZZ_PROJECT_NAME "deferredprocessing_fuzzer"
#include <iostream>
#include "deferred_photo_processing_session.h"
#include "deferred_photo_processor.h"
#include "ideferred_photo_processing_session_callback.h"
#include "deferred_photo_processing_session_stub.h"
#include "deferred_photo_processing_session_callback_stub.h"
#include "deferred_video_processing_session.h"
#include "deferred_video_processing_session_callback_stub.h"
namespace OHOS {
namespace CameraStandard {
class PictureIntf;
using namespace OHOS::CameraStandard::DeferredProcessing;
void DeferredProcessingFuzzTestGetPermission();
void DeferredProcessingPhotoFuzzTest(uint8_t *rawData, size_t size);
void DeferredProcessingVideoFuzzTest(uint8_t *rawData, size_t size);

class IDeferredPhotoProcessingSessionCallbackFuzz : public DeferredPhotoProcessingSessionCallbackStub {
public:
    explicit IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    virtual ~IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    inline int32_t OnProcessImageDone(const std::string &imageId,
        const sptr<IPCFileDescriptor>& ipcFd, int64_t bytes, uint32_t cloudImageEnhanceFlag) override
    {
        return 0;
    }
    inline int32_t OnProcessImageDone(const std::string &imageId, const std::shared_ptr<PictureIntf>& picture,
        const DpsMetadata& metadata) override
    {
        return 0;
    }
    inline int32_t OnDeliveryLowQualityImage(const std::string &imageId,
        const std::shared_ptr<PictureIntf>& picture) override
    {
        return 0;
    }
    inline int32_t OnError(const std::string &imageId, ErrorCode errorCode) override
    {
        return 0;
    }
    inline int32_t OnStateChanged(StatusCode status) override
    {
        return 0;
    }
    int32_t CallbackParcel(
        [[maybe_unused]] uint32_t code,
        [[maybe_unused]] MessageParcel& data,
        [[maybe_unused]] MessageParcel& reply,
        [[maybe_unused]] MessageOption& option) override
    {
        return 0;
    }
};

class IDeferredVideoProcessingSessionCallbackFuzz : public DeferredVideoProcessingSessionCallbackStub {
public:
    explicit IDeferredVideoProcessingSessionCallbackFuzz() = default;
    virtual ~IDeferredVideoProcessingSessionCallbackFuzz() = default;
    inline ErrCode OnProcessVideoDone(const std::string& videoId) override
    {
        return 0;
    }
    inline ErrCode OnError(const std::string& videoId, ErrorCode errorCode) override
    {
        return 0;
    }
    inline ErrCode OnStateChanged(StatusCode status) override
    {
        return 0;
    }
    inline ErrCode OnProcessingProgress(const std::string& videoId, float progress) override
    {
        return 0;
    }
};

void TestBufferInfo(uint8_t *rawData, size_t size);
} //CameraStandard
} //OHOS
#endif //DEFERREDPROCESSING_FUZZER_H

