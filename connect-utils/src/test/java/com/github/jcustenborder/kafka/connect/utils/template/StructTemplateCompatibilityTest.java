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
import org.apache.kafka.connect.data.Decimal;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.data.Timestamp;
import org.apache.kafka.connect.sink.SinkRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Characterization tests that pin down how {@link StructTemplate} renders ordinary templates, so
 * that hardening the FreeMarker configuration cannot silently change output for existing users.
 *
 * <p>Each case records either the rendered text or, if rendering fails, {@code ERROR:} followed by
 * the exception class.
 */
public class StructTemplateCompatibilityTest {

  enum Mode {
    MAP,
    STRUCT,
    RECORD
  }

  static final class Case {
    final Mode mode;
    final String template;
    final String expected;

    Case(Mode mode, String template, String expected) {
      this.mode = mode;
      this.template = template;
      this.expected = expected;
    }
  }

  static final List<Case> CASES = new ArrayList<>();

  static void add(Mode mode, String template, String expected) {
    CASES.add(new Case(mode, template, expected));
  }

  static {
    // Map overload
    add(Mode.MAP, "${s}", "banana");
    add(Mode.MAP, "prefix.${s}.suffix", "prefix.banana.suffix");
    add(Mode.MAP, "${i}", "42");
    add(Mode.MAP, "${l}", "1,234,567");
    add(Mode.MAP, "${d}", "3.142");
    add(Mode.MAP, "${bd}", "12,345.678");
    add(Mode.MAP, "${b?c}", "true");
    add(Mode.MAP, "${b?string('yes','no')}", "yes");
    add(Mode.MAP, "${missing}", "");
    // MissingValueHashWrapper turns a missing key into an empty value, so the default is not used.
    add(Mode.MAP, "${missing!'fallback'}", "");
    add(Mode.MAP, "${s?upper_case}", "BANANA");
    add(Mode.MAP, "${s?length}", "6");
    add(Mode.MAP, "${s?replace('a','_')}", "b_n_n_");
    add(Mode.MAP, "<#if i gt 10>big<#else>small</#if>", "big");
    add(Mode.MAP, "${nested.k}", "v");
    add(Mode.MAP, "${nested.missing!'none'}", "none");
    add(Mode.MAP, "${list[0]}", "a");
    add(Mode.MAP, "${list?size}", "3");
    add(Mode.MAP, "<#list list as x>${x};</#list>", "a;b;c;");
    add(Mode.MAP, "${list?join('-')}", "a-b-c");
    add(Mode.MAP, "${date?long}", "994,204,800,000");
    add(Mode.MAP, "${date?datetime?string('yyyy-MM-dd HH:mm')}", "2001-07-04 00:00");

    // Struct overload
    add(Mode.STRUCT, "${stringField}", "TestValue");
    add(Mode.STRUCT, "${intField}", "42");
    add(Mode.STRUCT, "${int64Field}", "9,876,543,210");
    add(Mode.STRUCT, "${float64Field}", "2.5");
    add(Mode.STRUCT, "${decimalField}", "1.25");
    add(Mode.STRUCT, "${boolField?c}", "false");
    add(Mode.STRUCT, "${nullStringField!'x'}", "x");
    add(Mode.STRUCT, "${nestedStruct.innerField}", "inner");
    add(Mode.STRUCT, "${arrayField[1]}", "y");
    add(Mode.STRUCT, "<#list arrayField as x>${x};</#list>", "x;y;z;");
    add(Mode.STRUCT, "${mapField.k}", "mv");
    add(Mode.STRUCT, "${timestampField?long}", "994,204,800,000");
    add(Mode.STRUCT, "${stringField?upper_case}-${intField}", "TESTVALUE-42");

    // ConnectRecord overload
    add(Mode.RECORD, "${topic}", "testing");
    add(Mode.RECORD, "${partition}", "1");
    add(Mode.RECORD, "${topic}.${stringField}", "testing.TestValue");
    add(Mode.RECORD, "${intField}", "42");
    add(Mode.RECORD, "${int64Field}", "9,876,543,210");
    add(Mode.RECORD, "${float64Field}", "2.5");
    add(Mode.RECORD, "${decimalField}", "1.25");
    add(Mode.RECORD, "${boolField?c}", "false");
    add(Mode.RECORD, "${nullStringField}", "");
    add(Mode.RECORD, "${missingField}", "");
    add(Mode.RECORD, "${nestedStruct.innerField}", "inner");
    add(Mode.RECORD, "${arrayField[1]}", "y");
    add(Mode.RECORD, "${arrayField?size}", "3");
    add(Mode.RECORD, "${mapField.k}", "mv");
    add(Mode.RECORD, "${timestampField?long}", "994,204,800,000");
    add(Mode.RECORD, "<#if intField == 42>match</#if>", "match");
  }

  StructTemplate structTemplate;
  Map<String, Object> map;
  Struct struct;
  SinkRecord record;

  @BeforeEach
  public void before() {
    this.structTemplate = new StructTemplate();
    // Pin locale and time zone so that number and date output does not depend on the build host.
    this.structTemplate.configuration.setLocale(Locale.US);
    this.structTemplate.configuration.setTimeZone(TimeZone.getTimeZone("UTC"));

    Date date = new Date(994204800000L); // 2001-07-04T00:00:00Z

    this.map = new LinkedHashMap<>();
    this.map.put("s", "banana");
    this.map.put("i", 42);
    this.map.put("l", 1234567L);
    this.map.put("d", 3.14159d);
    this.map.put("bd", new BigDecimal("12345.678"));
    this.map.put("b", true);
    this.map.put("nested", ImmutableMap.of("k", "v"));
    this.map.put("list", ImmutableList.of("a", "b", "c"));
    this.map.put("date", date);

    Schema nestedSchema = SchemaBuilder.struct()
        .name("Nested")
        .field("innerField", Schema.STRING_SCHEMA)
        .build();
    Schema schema = SchemaBuilder.struct()
        .name("TestStruct")
        .field("stringField", Schema.STRING_SCHEMA)
        .field("nullStringField", Schema.OPTIONAL_STRING_SCHEMA)
        .field("intField", Schema.INT32_SCHEMA)
        .field("int64Field", Schema.INT64_SCHEMA)
        .field("float64Field", Schema.FLOAT64_SCHEMA)
        .field("decimalField", Decimal.schema(3))
        .field("boolField", Schema.BOOLEAN_SCHEMA)
        .field("nestedStruct", nestedSchema)
        .field("arrayField", SchemaBuilder.array(Schema.STRING_SCHEMA).build())
        .field("mapField", SchemaBuilder.map(Schema.STRING_SCHEMA, Schema.STRING_SCHEMA).build())
        .field("timestampField", Timestamp.SCHEMA)
        .build();

    this.struct = new Struct(schema)
        .put("stringField", "TestValue")
        .put("intField", 42)
        .put("int64Field", 9876543210L)
        .put("float64Field", 2.5d)
        .put("decimalField", new BigDecimal("1.250"))
        .put("boolField", false)
        .put("nestedStruct", new Struct(nestedSchema).put("innerField", "inner"))
        .put("arrayField", ImmutableList.of("x", "y", "z"))
        .put("mapField", ImmutableMap.of("k", "mv"))
        .put("timestampField", date);
    this.struct.validate();

    this.record = new SinkRecord("testing", 1, null, null, schema, this.struct, 123456L);
  }

  String render(Case c) {
    String name = "t" + Integer.toHexString(c.template.hashCode());
    this.structTemplate.addTemplate(name, c.template);
    try {
      switch (c.mode) {
        case MAP:
          return this.structTemplate.execute(name, this.map);
        case STRUCT:
          return this.structTemplate.execute(name, this.struct);
        case RECORD:
          return this.structTemplate.execute(name, this.record, this.struct, ImmutableMap.of());
        default:
          throw new IllegalStateException(c.mode.toString());
      }
    } catch (RuntimeException e) {
      return "ERROR:" + e.getClass().getSimpleName();
    }
  }

  @TestFactory
  public Stream<DynamicTest> rendering() {
    return CASES.stream().map(c -> DynamicTest.dynamicTest(c.mode + " " + c.template, () -> {
      String actual = render(c);
      assertEquals(c.expected, actual, "Rendering changed for " + c.mode + " template " + c.template);
    }));
  }
}
