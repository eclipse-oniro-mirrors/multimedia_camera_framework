#include "listener_napi_base.h"

namespace OHOS {
namespace CameraStandard {

napi_value ListenerNapiBase::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
}

napi_value ListenerNapiBase::Once(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Once is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
}

napi_value ListenerNapiBase::Off(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Off is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 1;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    napi_valuetype secondArgsType = napi_undefined;
    if (argc > minArgCount &&
        (napi_typeof(env, argv[PARAM1], &secondArgsType) != napi_ok || secondArgsType != napi_function)) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
}

napi_value ListenerNapiBase::RegisterCallback(napi_env env, napi_value jsThis,const string &eventType, napi_value callback, bool isOnce)
{
    // This method is meant to be implemented in derived classes to provide specific functionality.
    // Leave this method as it is until a proper implementation is provided in derived classes.
}
napi_value ListenerNapiBase::UnregisterCallback(napi_env env, napi_value jsThis,const std::string& eventType, napi_value callback)
{
    // This method is meant to be implemented in derived classes to provide specific functionality.
    // Leave this method as it is until a proper implementation is provided in derived classes.
}
} // namespace CameraStandard
} // namespace OHOS
