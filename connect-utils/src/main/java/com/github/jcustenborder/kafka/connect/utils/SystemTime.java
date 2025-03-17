/**
 * Copyright © 2016 Jeremy Custenborder (jcustenborder@gmail.com)
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

package com.github.jcustenborder.kafka.connect.utils;

import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.errors.TimeoutException;

import java.util.function.Supplier;

public class SystemTime implements Time {
  private static final SystemTime SYSTEM_TIME = new SystemTime();

  public static SystemTime getSystemTime() {
    return SYSTEM_TIME;
  }

  @Override
  public long milliseconds() {
    return System.currentTimeMillis();
  }

  @Override
  public long nanoseconds() {
    return System.nanoTime();
  }

  @Override
  public void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      // this is okay, we just wake up early
      Thread.currentThread().interrupt();
    }
  }

  @Override
  public void waitObject(Object obj,
      Supplier<Boolean> condition, long deadlineMs) throws InterruptedException {
    synchronized (obj) {
      while (true) {
        if (condition.get()) {
          return;
        }

        long currentTimeMs = milliseconds();
        if (currentTimeMs >= deadlineMs) {
          throw new TimeoutException("Condition not satisfied before deadline");
        }

        obj.wait(deadlineMs - currentTimeMs);
      }
    }
  }

  private SystemTime() {

  }
}

