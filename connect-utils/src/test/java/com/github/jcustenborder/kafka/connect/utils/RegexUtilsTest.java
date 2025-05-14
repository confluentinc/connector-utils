/**
 * Copyright [2023 - 2023] Confluent Inc.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.Collections;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegexUtilsTest {
    private static final Logger log = LoggerFactory.getLogger(RegexUtilsTest.class);
    private static final long TIMEOUT_MS = 100;
    private static final long LONG_TIMEOUT_MS = 1000;

    @MethodSource("providerForTestReplaceAll")
    @ParameterizedTest
    void testReplaceAll(
            String input,
            List<String> patterns,
            List<String> replacements,
            String expectedOutput) throws InterruptedException, ExecutionException {
        
        Map<Pattern, String> patternMap = new HashMap<>();
        for (int i = 0; i < patterns.size(); i++) {
            patternMap.put(Pattern.compile(patterns.get(i)), replacements.get(i));
        }
        
        String result = RegexUtils.replaceAll(input, patternMap, TIMEOUT_MS);
        assertEquals(expectedOutput, result);
    }

    static Stream<Arguments> providerForTestReplaceAll() {
        return Stream.of(
            // Email masking test
            Arguments.of(
                "Contact us at john.doe@example.com for support",
                Arrays.asList("([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+)"),
                Arrays.asList("***@$2"),
                "Contact us at ***@example.com for support"
            ),
            // Credit card masking test
            Arguments.of(
                "Card number: 4111-1111-1111-1111",
                Arrays.asList("(\\d{4})[- ]?(\\d{4})[- ]?(\\d{4})[- ]?(\\d{4})"),
                Arrays.asList("$1-****-****-$4"),
                "Card number: 4111-****-****-1111"
            ),
            // Phone number formatting test
            Arguments.of(
                "Call us at 123-456-7890",
                Arrays.asList("(\\d{3})[- ]?(\\d{3})[- ]?(\\d{4})"),
                Arrays.asList("($1) $2-$3"),
                "Call us at (123) 456-7890"
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
                "Email: ***@domain.com, Phone: (123) 456-7890"
            ),
            // Special character handling test
            Arguments.of(
                "Replace ${variable} with value",
                Arrays.asList("\\$\\{([^}]+)\\}"),
                Arrays.asList("\\$$1"),
                "Replace $variable with value"
            ),
            // Null input test
            Arguments.of(null, Arrays.asList("test"), Arrays.asList("replacement"), null),
            // Empty patterns test
            Arguments.of("test string", Arrays.asList(), Arrays.asList(), "test string"),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                Arrays.asList(String.join("", Collections.nCopies(1000, "(a+)+"))),
                Arrays.asList("replaced"),
                String.join("", Collections.nCopies(1000, "a"))  // Should return original string due to timeout
            )
        );
    }

    @MethodSource("providerForTestFind")
    @ParameterizedTest
    void testFind(
            String input,
            String pattern,
            boolean expectedResult,
            boolean shouldTimeout) throws InterruptedException, ExecutionException {
        
        Pattern compiledPattern = Pattern.compile(pattern);
        boolean result = RegexUtils.find(compiledPattern, input, shouldTimeout ? TIMEOUT_MS : LONG_TIMEOUT_MS);
        assertEquals(expectedResult, result);
    }

    static Stream<Arguments> providerForTestFind() {
        return Stream.of(
            // Basic match test
            Arguments.of("hello world", "hello", true, false),
            // No match test
            Arguments.of("hi world", "hello", false, false),
            // Null input test
            Arguments.of(null, "hello", false, false),
            // Empty string test
            Arguments.of("", "hello", false, false),
            // Case sensitive test
            Arguments.of("Hello World", "hello", false, false),
            // Case insensitive test
            Arguments.of("Hello World", "(?i)hello", true, false),
            // Multiple matches test
            Arguments.of("hello hello world", "hello", true, false),
            // Special characters test
            Arguments.of("$100.50", "\\$\\d+\\.\\d+", true, false),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                String.join("", Collections.nCopies(1000, "(a+)+")),
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
            boolean shouldTimeout) throws InterruptedException, ExecutionException {
        
        Pattern compiledPattern = Pattern.compile(pattern);
        boolean result = RegexUtils.matches(compiledPattern, input, shouldTimeout ? TIMEOUT_MS : LONG_TIMEOUT_MS);
        assertEquals(expectedResult, result);
    }

    static Stream<Arguments> providerForTestMatches() {
        return Stream.of(
            // Exact match test
            Arguments.of("hello world", "hello world", true, false),
            // Partial match test
            Arguments.of("hello world", "hello", false, false),
            // Null input test
            Arguments.of(null, "hello", false, false),
            // Empty string test
            Arguments.of("", "^$", true, false),
            // Case sensitive test
            Arguments.of("Hello World", "hello world", false, false),
            // Case insensitive test
            Arguments.of("Hello World", "(?i)hello world", true, false),
            // Start/end anchors test
            Arguments.of("hello world", "^hello world$", true, false),
            // Special characters test
            Arguments.of("$100.50", "^\\$\\d+\\.\\d+$", true, false),
            // ReDoS protection tests
            // Test 1: Catastrophic backtracking with (a+)+
            Arguments.of(
                String.join("", Collections.nCopies(1000, "a")),
                String.join("", Collections.nCopies(1000, "(a+)+")),
                false,
                true
            )
        );
    }
} 