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

#ifndef DEFERRED_VIDEO_PROC_SESSION_FUZZER_H
#define DEFERRED_VIDEO_PROC_SESSION_FUZZER_H

#include "hstream_repeat_stub.h"
#include "deferred_video_proc_session.h"
#include "token_setproc.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
class IDeferredVideoProcSessionCallbackFuzz : public IDeferredVideoProcSessionCallback {
public:
    void OnProcessVideoDone(const std::string& videoId, const sptr<IPCFileDescriptor> ipcFd) override {}
    void OnError(const std::string& videoId, const DpsErrorCode errorCode) override {}
    void OnStateChanged(const DpsStatusCode status) override {}
};

class IDeferredVideoProcessingSessionFuzz : public DeferredProcessing::IDeferredVideoProcessingSession {
public:
    int32_t BeginSynchronize() override
    {
        return 0;
    }
    int32_t EndSynchronize() override
    {
        return 0;
    }
    int32_t AddVideo(
        const std::string& videoId,
        const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd) override
    {
        return 0;
    }
    int32_t RemoveVideo(const std::string& videoId, bool restorable) override
    {
        return 0;
    }
    int32_t RestoreVideo(const std::string& videoId) override
    {
        return 0;
    }

    sptr<IRemoteObject> AsObject() override
    {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            return nullptr;
        }
        sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
        return object;
    }
};

class DeferredVideoProcSessionFuzzer {
public:
static void DeferredVideoProcSessionFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //DEFERRED_VIDEO_PROC_SESSION_FUZZER_H