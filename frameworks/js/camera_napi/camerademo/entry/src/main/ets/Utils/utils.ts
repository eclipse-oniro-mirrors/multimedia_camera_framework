/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import hilog from '@ohos.hilog';
export class Log {
  private static readonly TAG: string = '[CameraDemoApp]'
  public static  readonly SYMBOL:string = " --> ";
  public static readonly LEVEL_DEBUG = 0;
  public static readonly LEVEL_LOG = 1;
  public static readonly LEVEL_INFO = 2;
  public static readonly LEVEL_WARN = 3;
  public static readonly LEVEL_ERROR = 4;
  public static LOG_LEVEL = Log.LEVEL_INFO;
  public static readonly DOMAIN = 0x002F;

  public static debug(tag: string, format: string,...args: any[]) {
    if (this.LOG_LEVEL <= this.LEVEL_DEBUG) {
      hilog.debug(Log.DOMAIN, Log.TAG, tag + Log.SYMBOL + format, args)
    }
  }

  public static info(tag: string, format: string,...args: any[]) {
    if (this.LOG_LEVEL <= this.LEVEL_INFO) {
        hilog.info(Log.DOMAIN, Log.TAG, tag + Log.SYMBOL + format, args)
    }
  }

  public static warn(tag: string, format: string,...args: any[]) {
    if (this.LOG_LEVEL <= this.LEVEL_WARN) {
        hilog.warn(Log.DOMAIN, Log.TAG, tag + Log.SYMBOL + format, args)
    }
  }

  public static error(tag: string, format: string,...args: any[]) {
    if (this.LOG_LEVEL <= this.LEVEL_ERROR) {
        hilog.error(Log.DOMAIN, Log.TAG, tag + Log.SYMBOL + format, args)
    }
  }
}