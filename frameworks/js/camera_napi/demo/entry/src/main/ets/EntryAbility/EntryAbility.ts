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

import Ability from '@ohos.app.ability.UIAbility';
import type window from '@ohos.window';
import deviceInfo from '@ohos.deviceInfo';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import type Want from '@ohos.app.ability.Want';
import type AbilityConstant from '@ohos.app.ability.AbilityConstant';
import Logger from '../model/Logger';
import { Constants } from '../common/Constants';

const TAG: string = 'EntryAbility';

export default class EntryAbility extends Ability {

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    Logger.info(TAG, 'Ability onCreate');
    Logger.debug(TAG, `want param: ${JSON.stringify(want)}`);
    Logger.debug(TAG, `launchParam: ${JSON.stringify(launchParam)}`);
    globalThis.abilityContext = this.context;
  }

  onDestroy(): void {
    Logger.info(TAG, 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    Logger.info(TAG, 'Ability onWindowStageCreate');
    this.requestPermissionsFn();
    AppStorage.SetOrCreate<string>('deviceType', deviceInfo.deviceType);
    if (deviceInfo.deviceType === Constants.TABLET) {
      windowStage.getMainWindow().then((win: window.Window): void => {
        win.setLayoutFullScreen(true).then((): void => {
          win.setSystemBarEnable(['navigation']).then((): void => {
          });
        });
        win.setSystemBarProperties({
          navigationBarColor: '#00000000',
          navigationBarContentColor: '#B3B3B3'
        }).then((): void => {
        });
      });
    }

    windowStage.loadContent('pages/Index', (err, data): void => {
      if (err) {
        Logger.error(TAG, `Failed to load the content. Cause: ${JSON.stringify(err)}`);
        return;
      }
      Logger.info(TAG, `Succeeded in loading the content. Data: ${JSON.stringify(data)}`);
    });
  }

  /**
   * 获取权限
   */
  requestPermissionsFn(): void {
    let atManager = abilityAccessCtrl.createAtManager();
    atManager.requestPermissionsFromUser(globalThis.abilityContext, [
      'ohos.permission.CAMERA',
      'ohos.permission.MICROPHONE',
      'ohos.permission.READ_MEDIA',
      'ohos.permission.WRITE_MEDIA'
    ]).then((): void => {
      AppStorage.SetOrCreate<boolean>('isShow', true);
      Logger.info(TAG, 'request Permissions success!');
    }).catch((error: {code: number}): void => {
      Logger.info(TAG, `requestPermissionsFromUser call Failed! error: ${error.code}`);
    });
  }
}
