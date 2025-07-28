/**
 * Copyright [2025 - 2025] Confluent Inc.
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

package com.github.jcustenborder.kafka.connect.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.Collections;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegexUtilsTest {
    private static final long TIMEOUT_MS = 100;
    private static final long LONG_TIMEOUT_MS = 1000;

    // Test string constants
    private static final String HELLO_WORLD = "hello world";
    private static final String HELLO = "hello";
    private static final String HELLO_WORLD_TITLE_CASE = "Hello World";

    // ReDoS pattern constant
    private static final String REDOS_PATTERN = "(a+)+";

    @MethodSource("providerForTestReplaceAll")
    @ParameterizedTest
    void testReplaceAll(
            String input,
            List<String> patterns,
            List<String> replacements,
            String expectedOutput,
            boolean shouldTimeout) throws InterruptedException, ExecutionException, TimeoutException {

        Map<Pattern, String> patternMap = new HashMap<>();
        for (int i = 0; i < patterns.size(); i++) {
            Pattern p = patterns.get(i) == null ? null : Pattern.compile(patterns.get(i));
            patternMap.put(p, replacements.get(i));
        }

        if (patterns.contains(null)) {
            assertThrows(IllegalArgumentException.class, () ->
                RegexUtils.replaceAll(input, patternMap, TIMEOUT_MS));
            return;
        }

        if (shouldTimeout) {
            assertThrows(TimeoutException.class, () ->
                RegexUtils.replaceAll(input, patternMap, TIMEOUT_MS));
        } else {
            String result = RegexUtils.replaceAll(input, patternMap, TIMEOUT_MS);
            assertEquals(expectedOutput, result);
        }
    }

    static Stream<Arguments> providerForTestReplaceAll() {
        return Stream.of(
            // Email masking test
            Arguments.of(
                "Contact us at john.doe@example.com for support",
                Arrays.asList("([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+)"),
                Arrays.asList("***@$2"),
                "Contact us at ***@example.com for support",
                false
            ),
            // Credit card masking test
            Arguments.of(
                "Card number: 4111-1111-1111-1111",
                Arrays.asList("(\\d{4})[- ]?(\\d{4})[- ]?(\\d{4})[- ]?(\\d{4})"),
                Arrays.asList("$1-****-****-$4"),
                "Card number: 4111-****-****-1111",
                false
            ),
            // Phone number formatting test
            Arguments.of(
                "Call us at 123-456-7890",
                Arrays.asList("(\\d{3})[- ]?(\\d{3})[- ]?(\\d{4})"),
                Arrays.asList("($1) $2-$3"),
                "Call us at (123) 456-7890",
                false
            ),
            // Multiple replacements test
            Arguments.of(
                "Email: user@domain.com, Phone: 123-456-7890",
                Arrays.asList(
                    "([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+)",
                    "(\\d{3})[- ]?(\\d{3})[- ]?(\\d{4})"
                ),
                Arrays.asList(
                    "***@$2",
                    "($1) $2-$3"
                ),
                "Email: ***@domain.com, Phone: (123) 456-7890",
                false
            ),
            // Special character handling test
            Arguments.of(
                "Replace ${variable} with value",
                Arrays.asList("\\$\\{([^}]+)\\}"),
                Arrays.asList("\\$$1"),
                "Replace $variable with value",
                false
            ),
            // Null input test
            Arguments.of(null, Arrays.asList("test"), Arrays.asList("replacement"), null, false),
            // Empty patterns test
            Arguments.of("test string", Arrays.asList(), Arrays.asList(), "test string", false),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                Arrays.asList(String.join("", Collections.nCopies(1000, REDOS_PATTERN))),
                Arrays.asList("replaced"),
                null,  // Expected output doesn't matter as it should timeout
                true
            )
        );
    }

    @MethodSource("providerForTestFind")
    @ParameterizedTest
    void testFind(
            String input,
            String pattern,
            boolean expectedResult,
            boolean shouldTimeout) throws InterruptedException, ExecutionException, TimeoutException {

        if (pattern == null) {
            assertThrows(IllegalArgumentException.class,
                () -> RegexUtils.find(null, input, TIMEOUT_MS));
            return;
        }

        Pattern compiledPattern = Pattern.compile(pattern);
        if (shouldTimeout) {
            assertThrows(TimeoutException.class, () ->
                RegexUtils.find(compiledPattern, input, TIMEOUT_MS));
        } else {
            boolean result = RegexUtils.find(compiledPattern, input, LONG_TIMEOUT_MS);
            assertEquals(expectedResult, result);
        }
    }

    static Stream<Arguments> providerForTestFind() {
        return Stream.of(
            // Basic match test
            Arguments.of(HELLO_WORLD, HELLO, true, false),
            // No match test
            Arguments.of("hi world", HELLO, false, false),
            // Null input test
            Arguments.of(null, HELLO, false, false),
            // Empty string test
            Arguments.of("", HELLO, false, false),
            // Case-sensitive test
            Arguments.of(HELLO_WORLD_TITLE_CASE, HELLO, false, false),
            // Case-insensitive test
            Arguments.of(HELLO_WORLD_TITLE_CASE, "(?i)" + HELLO, true, false),
            // Multiple matches test
            Arguments.of(HELLO + " " + HELLO + " world", HELLO, true, false),
            // Special characters test
            Arguments.of("$100.50", "\\$\\d+\\.\\d+", true, false),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                String.join("", Collections.nCopies(1000, REDOS_PATTERN)),
                false,
                true
            )
        );
    }

    @MethodSource("providerForTestMatches")
    @ParameterizedTest
    void testMatches(
            String input,
            String pattern,
            boolean expectedResult,
            boolean shouldTimeout) throws InterruptedException, ExecutionException, TimeoutException {

        if (pattern == null) {
            assertThrows(IllegalArgumentException.class,
                () -> RegexUtils.matches(null, input, TIMEOUT_MS));
            return;
        }

        Pattern compiledPattern = Pattern.compile(pattern);
        if (shouldTimeout) {
            assertThrows(TimeoutException.class, () ->
                RegexUtils.matches(compiledPattern, input, TIMEOUT_MS));
        } else {
            boolean result = RegexUtils.matches(compiledPattern, input, LONG_TIMEOUT_MS);
            assertEquals(expectedResult, result);
        }
    }

    static Stream<Arguments> providerForTestMatches() {
        return Stream.of(
            // Exact match test
            Arguments.of(HELLO_WORLD, HELLO_WORLD, true, false),
            // Partial match test
            Arguments.of(HELLO_WORLD, HELLO, false, false),
            // Null input test
            Arguments.of(null, HELLO, false, false),
            // Empty string test
            Arguments.of("", "^$", true, false),
            // Case-sensitive test
            Arguments.of(HELLO_WORLD_TITLE_CASE, HELLO_WORLD, false, false),
            // Case-insensitive test
            Arguments.of(HELLO_WORLD_TITLE_CASE, "(?i)" + HELLO_WORLD, true, false),
            // Start/end anchors test
            Arguments.of(HELLO_WORLD, "^" + HELLO_WORLD + "$", true, false),
            // Special characters test
            Arguments.of("$100.50", "^\\$\\d+\\.\\d+$", true, false),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                String.join("", Collections.nCopies(1000, REDOS_PATTERN)),
                false,
                true
            )
        );
    }
}
