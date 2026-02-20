/**
 * Copyright © 2016 Jeremy Custenborder (jcustenborder@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.jcustenborder.kafka.connect.utils.errors;

import org.apache.kafka.connect.errors.ConnectException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

public class UserActionableExceptionTest {

  private static final String USER_MESSAGE = "Please set cluster.region in connector config.";

  @Test
  public void messageOnlyConstructor() {
    UserActionableException e = new UserActionableException(USER_MESSAGE);
    assertEquals(USER_MESSAGE, e.getMessage());
    assertEquals(null, e.getCause());
  }

  @Test
  public void messageAndCauseConstructor() {
    Throwable cause = new IllegalArgumentException("underlying");
    UserActionableException e = new UserActionableException(USER_MESSAGE, cause);
    assertEquals(USER_MESSAGE, e.getMessage());
    assertSame(cause, e.getCause());
  }

  @Test
  public void causeOnlyConstructor() {
    Throwable cause = new IllegalStateException("wrapped");
    UserActionableException e = new UserActionableException(cause);
    assertNotNull(e.getMessage());
    assertSame(cause, e.getCause());
  }

  @Test
  public void isConnectException() {
    UserActionableException e = new UserActionableException(USER_MESSAGE);
    assertSame(ConnectException.class, e.getClass().getSuperclass());
  }
}
