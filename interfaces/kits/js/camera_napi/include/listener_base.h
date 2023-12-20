#ifndef LISTENER_BASE_H_
#define LISTENER_BASE_H_

#include "camera_napi_utils.h"

class ListenerBase {
public:
    virtual ~ListenerBase() {}

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

private:
    virtual static napi_value RegisterCallback(napi_env env, napi_value jsThis,const string &eventType, napi_value callback, bool isOnce)= 0;
    virtual static napi_value UnregisterCallback(napi_env env, napi_value jsThis,const std::string& eventType, napi_value callback)
};
#endif // CONCRETELISTENER_H
