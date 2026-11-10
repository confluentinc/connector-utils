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
package com.github.jcustenborder.kafka.connect.utils.template;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import freemarker.core.TemplateClassResolver;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.errors.ConnectException;
import org.apache.kafka.connect.sink.SinkRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Templates may be built from user-supplied configuration, so they must not be able to reach Java
 * object creation or the Java API of the values they render (server-side template injection).
 */
public class StructTemplateSecurityTest {

  static final List<String> NEW_BUILTIN_PAYLOADS = Arrays.asList(
      "${\"freemarker.template.utility.Execute\"?new()(\"echo PWNED\")}",
      "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"echo PWNED\")}",
      "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.StringBuilder\", \"PWNED\")}",
      "${\"freemarker.template.utility.JythonRuntime\"?new()}"
  );

  static final List<String> API_BUILTIN_PAYLOADS = Arrays.asList(
      "${arrayField?api.size()}",
      "${arrayField?api.getClass().getName()}",
      "${mapField?api.getClass().getName()}"
  );

  // Templates must not be able to switch the protections back on themselves.
  static final List<String> SETTING_OVERRIDE_PAYLOADS = Arrays.asList(
      "<#setting new_builtin_class_resolver=\"unrestricted\">"
          + "${\"freemarker.template.utility.Execute\"?new()(\"echo PWNED\")}",
      "<#setting api_builtin_enabled=true>${arrayField?api.size()}"
  );

  StructTemplate structTemplate;
  Struct struct;
  SinkRecord record;
  Map<String, ?> map;

  @BeforeEach
  public void before() {
    this.structTemplate = new StructTemplate();
    Schema schema = SchemaBuilder.struct()
        .name("TestStruct")
        .field("stringField", Schema.STRING_SCHEMA)
        .field("arrayField", SchemaBuilder.array(Schema.STRING_SCHEMA).build())
        .field("mapField", SchemaBuilder.map(Schema.STRING_SCHEMA, Schema.STRING_SCHEMA).build())
        .build();
    this.struct = new Struct(schema)
        .put("stringField", "TestValue")
        .put("arrayField", ImmutableList.of("a"))
        .put("mapField", ImmutableMap.of("k", "v"));
    this.struct.validate();
    this.record = new SinkRecord("testing", 1, null, null, schema, this.struct, 123456L);
    this.map = ImmutableMap.of(
        "arrayField", ImmutableList.of("a"),
        "mapField", ImmutableMap.of("k", "v")
    );
  }

  @Test
  public void configurationIsSandboxed() {
    assertSame(
        TemplateClassResolver.ALLOWS_NOTHING_RESOLVER,
        this.structTemplate.configuration.getNewBuiltinClassResolver()
    );
    assertFalse(this.structTemplate.configuration.isAPIBuiltinEnabled());
  }

  @TestFactory
  public Stream<DynamicTest> newBuiltinIsBlocked() {
    return payloadTests(NEW_BUILTIN_PAYLOADS);
  }

  @TestFactory
  public Stream<DynamicTest> apiBuiltinIsBlocked() {
    return payloadTests(API_BUILTIN_PAYLOADS);
  }

  @TestFactory
  public Stream<DynamicTest> templateCannotReEnableBuiltins() {
    return payloadTests(SETTING_OVERRIDE_PAYLOADS);
  }

  /**
   * Runs every payload through each of the public execute overloads and checks that rendering
   * fails rather than producing output.
   */
  Stream<DynamicTest> payloadTests(List<String> payloads) {
    return payloads.stream().flatMap(payload -> {
      String name = "t" + Integer.toHexString(payload.hashCode());
      this.structTemplate.addTemplate(name, payload);
      return Stream.of(
          dynamicTest("map", payload, () -> this.structTemplate.execute(name, this.map)),
          dynamicTest("struct", payload, () -> this.structTemplate.execute(name, this.struct)),
          dynamicTest("record", payload,
              () -> this.structTemplate.execute(name, this.record, this.struct, ImmutableMap.of()))
      );
    });
  }

  static DynamicTest dynamicTest(String overload, String payload, Executable executable) {
    return DynamicTest.dynamicTest(overload + " " + payload, () -> {
      ConnectException e = assertThrows(ConnectException.class, executable);
      assertFalse(
          String.valueOf(e.getMessage()).contains("PWNED"),
          "Payload output leaked into the exception message"
      );
      assertTrue(e.getCause() != null, "Expected the FreeMarker exception as the cause");
    });
  }
}
