/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_STUB_H
#define OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_STUB_H

#include "iremote_stub.h"
#include "ideferred_photo_processing_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessingSessionStub : public IRemoteStub<IDeferredPhotoProcessingSession> {
public:
    DeferredPhotoProcessingSessionStub();
    ~DeferredPhotoProcessingSessionStub();
    int OnRemoteRequest(uint32_t code, MessageParcel &data,
                        MessageParcel &reply, MessageOption &option) override;

private:
    int HandleBeginSynchronize(MessageParcel& data);
    int HandleEndSynchronize(MessageParcel& data);
    int HandleAddImage(MessageParcel& data);
    int HandleRemoveImage(MessageParcel& data);
    int HandleRestoreImage(MessageParcel& data);
    int HandleProcessImage(MessageParcel& data);
    int HandleCancelProcessImage(MessageParcel& data);
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_STUB_H
