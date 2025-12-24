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

#include "deferred_photo_processing_session_stub_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "deferred_photo_processing_session.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
constexpr int32_t USER_ID = 100;
const size_t MAX_LENGTH_STRING = 64;
constexpr char DEFERRED_KEY[] = "deferredProcessingType";
std::shared_ptr<DeferredPhotoProcessingSession> session_ = std::make_shared<DeferredPhotoProcessingSession>(USER_ID);

void BeginSynchronizeTest(uint32_t code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    session_->OnRemoteRequest(code, data, reply, option);
}

void EndSynchronizeTest(uint32_t code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    session_->OnRemoteRequest(code, data, reply, option);
}

void AddImageTest(uint32_t code, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    DpsMetadata metadata;
    metadata.Set(DEFERRED_KEY,fdp.ConsumeIntegral<int32_t>());
    data.WriteParcelable(&metadata);
    data.WriteBool(fdp.ConsumeBool());
    session_->OnRemoteRequest(code, data, reply, option);
}

void RemoveImageTest(uint32_t code, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    data.WriteBool(fdp.ConsumeBool());
    session_->OnRemoteRequest(code, data, reply, option);
}

void RestoreImageTest(uint32_t code, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    session_->OnRemoteRequest(code, data, reply, option);
}

void ProcessImageTest(uint32_t code, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    session_->OnRemoteRequest(code, data, reply, option);
}

void CancelProcessImageTest(uint32_t code, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)));
    session_->OnRemoteRequest(code, data, reply, option);
}

void NotifyProcessImageTest(uint32_t code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInterfaceToken(DeferredPhotoProcessingSession::GetDescriptor());
    session_->OnRemoteRequest(code, data, reply, option);
}

bool FuzzTest(FuzzedDataProvider& fdp)
{
    static const IDeferredPhotoProcessingSessionIpcCode ipccodes[] = {
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_BEGIN_SYNCHRONIZE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_END_SYNCHRONIZE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_ADD_IMAGE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_REMOVE_IMAGE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_RESTORE_IMAGE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_PROCESS_IMAGE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_CANCEL_PROCESS_IMAGE,
        IDeferredPhotoProcessingSessionIpcCode::COMMAND_NOTIFY_PROCESS_IMAGE,
    };
    IDeferredPhotoProcessingSessionIpcCode code = fdp.PickValueInArray(ipccodes);
    switch (code) {
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_BEGIN_SYNCHRONIZE: {
            BeginSynchronizeTest(static_cast<uint32_t>(code));
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_END_SYNCHRONIZE: {
            EndSynchronizeTest(static_cast<uint32_t>(code));
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_ADD_IMAGE: {
            AddImageTest(static_cast<uint32_t>(code), fdp);
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_REMOVE_IMAGE: {
            RemoveImageTest(static_cast<uint32_t>(code), fdp);
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_RESTORE_IMAGE: {
            RestoreImageTest(static_cast<uint32_t>(code), fdp);
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_PROCESS_IMAGE: {
            ProcessImageTest(static_cast<uint32_t>(code), fdp);
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_CANCEL_PROCESS_IMAGE: {
            CancelProcessImageTest(static_cast<uint32_t>(code), fdp);
            break;
        }
        case IDeferredPhotoProcessingSessionIpcCode::COMMAND_NOTIFY_PROCESS_IMAGE: {
            NotifyProcessImageTest(static_cast<uint32_t>(code));
            break;
        }
    }
    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CameraStandard::FuzzTest(fdp);
    return 0;
}