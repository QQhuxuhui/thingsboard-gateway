/**
 * Copyright © 2023 The Thingsboard Authors
 *
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
package org.thingsboard.mqtt;

import org.junit.Test;

/**
 * @author GGbond
 * @version 1.0
 * @description: TODO
 * @date 2022/4/14 13:58
 */
public class GenerateConfigTest {

    @Test
    public void generate(){
        String baseStr = "";
        for (int i = 1; i <= 200; i++) {
            baseStr = baseStr + "\t\t\t\t\t\t{\n" +
                    "\t\t\t\t\t\t\t\"key\": \"TAG"+i+"\",\n" +
                    "\t\t\t\t\t\t\t\"type\": \"double\",\n" +
                    "\t\t\t\t\t\t\t\"value\": \"${TAG"+i+"\"}\"\n" +
                    "\t\t\t\t\t\t},\n";
        }
        System.out.println(baseStr);
    }
}
