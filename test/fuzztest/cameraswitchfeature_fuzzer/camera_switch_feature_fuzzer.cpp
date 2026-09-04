#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include "camera_error_code.h"
#include "ability/camera_ability_enum.h"
#include "session/features/camera_switch_feature.h"
#include "icapture_session.h"
#include "input/capture_input.h"
#include "iremote_object.h"
#include "fuzz_util.h"
#include "hiphy_event_manager.h"
#include "test_token.h"
#include "camera_manager.h"
#include "camera_log.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;

static constexpr int32_t NUM_64 = 64;

CameraSwitchFeature& GetCameraSwitchFeature()
{
    static CameraSwitchFeature cameraSwitchFeature {
        CameraManager::GetInstance()->CreateCaptureSession(SceneMode::CAPTURE)
    };
    return cameraSwitchFeature;
}

static void TestTryFoldableProductAutoSwitch(FuzzedDataProvider& fdp)
{
    GetCameraSwitchFeature().TryFoldableProductAutoSwitch();
}

static void TestTryReplaceableLensAutoSwitch(FuzzedDataProvider& fdp)
{
    GetCameraSwitchFeature().TryReplaceableLensAutoSwitch();
}

static void TestOnHiPhyEvent(FuzzedDataProvider& fdp)
{
    HiPhyEvent event;
    event.type = PickEnumInRange<HiPhyEventType>(
        fdp, HiPhyEventType::CAMERA_APPEAR, HiPhyEventType::HAL_DEAD);
    event.msg = fdp.ConsumeRandomLengthString(NUM_64);

    GetCameraSwitchFeature().OnHiPhyEvent(event);
}

static void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

static void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        TestTryFoldableProductAutoSwitch,
        TestTryReplaceableLensAutoSwitch,
        TestOnHiPhyEvent,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}