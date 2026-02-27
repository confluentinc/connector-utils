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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RegexUtilsTest {
    private static final long TIMEOUT_MS = 100;
    private static final long LONG_TIMEOUT_MS = 1000;

    // Test string constants
    private static final String HELLO_WORLD = "hello world";
    private static final String HELLO = "hello";
    private static final String HELLO_WORLD_TITLE_CASE = "Hello World";

    // ReDoS: (.*a){N} against "aaa...b" causes exponential backtracking in Java's regex engine
    private static final String REDOS_INPUT = String.join("", Collections.nCopies(25, "a")) + "b";
    private static final String REDOS_PATTERN = "(.*a){25}";

    @MethodSource("providerForTestReplaceAll")
    @ParameterizedTest
    void testReplaceAll(
            String input,
            List<String> patterns,
            List<String> replacements,
            String expectedOutput,
            boolean shouldTimeout) throws TimeoutException {

        Map<Pattern, String> patternMap = new HashMap<>();
        for (int i = 0; i < patterns.size(); i++) {
            patternMap.put(Pattern.compile(patterns.get(i)), replacements.get(i));
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
            // ReDoS protection tests — (.*a){N} causes exponential backtracking
            Arguments.of(
                REDOS_INPUT,
                Arrays.asList(REDOS_PATTERN),
                Arrays.asList("replaced"),
                null,
                true
            ),
            // Test 4: OpenSearch wrap pattern (non-pathological, should NOT timeout)
            Arguments.of(
                "{\"field\":\"value\",\"nested\":{\"key\":123}}",
                Arrays.asList("^(?s)(.*)$"),
                Arrays.asList("{\"doc\": $1, \"doc_as_upsert\": true}"),
                "{\"doc\": {\"field\":\"value\",\"nested\":{\"key\":123}}, \"doc_as_upsert\": true}",
                false
            )
        );
    }

    @MethodSource("providerForTestFind")
    @ParameterizedTest
    void testFind(
            String input,
            String pattern,
            boolean expectedResult,
            boolean shouldTimeout) throws TimeoutException {

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
            // ReDoS protection test — (.*a){N} causes exponential backtracking
            Arguments.of(REDOS_INPUT, REDOS_PATTERN, false, true)
        );
    }

    @MethodSource("providerForTestMatches")
    @ParameterizedTest
    void testMatches(
            String input,
            String pattern,
            boolean expectedResult,
            boolean shouldTimeout) throws TimeoutException {

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
            // ReDoS protection test — (.*a){N} causes exponential backtracking
            Arguments.of(REDOS_INPUT, REDOS_PATTERN, false, true)
        );
    }

    // ---- Multi-threading tests ----

    private static final int THREAD_COUNT = 50;
    private static final String OPENSEARCH_INPUT = "{\"field\":\"value\",\"nested\":{\"key\":123}}";
    private static final String OPENSEARCH_EXPECTED =
            "{\"doc\": {\"field\":\"value\",\"nested\":{\"key\":123}}, \"doc_as_upsert\": true}";

    @Test
    void concurrentReplaceAllProducesCorrectResults() throws Exception {
        Pattern pattern = Pattern.compile("^(?s)(.*)$");
        Map<Pattern, String> replacements = new LinkedHashMap<>();
        replacements.put(pattern, "{\"doc\": $1, \"doc_as_upsert\": true}");

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger failureCount = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    String result = RegexUtils.replaceAll(OPENSEARCH_INPUT, replacements, TIMEOUT_MS);
                    assertEquals(OPENSEARCH_EXPECTED, result);
                    successCount.incrementAndGet();
                } catch (TimeoutException e) {
                    failureCount.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        startLatch.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        assertEquals(THREAD_COUNT, successCount.get(),
                "All threads should succeed without timeout");
        assertEquals(0, failureCount.get(),
                "No threads should timeout on a non-pathological pattern");
    }

    @Test
    void concurrentFindProducesCorrectResults() throws Exception {
        Pattern pattern = Pattern.compile("\\d+");

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    boolean result = RegexUtils.find(pattern, "abc123def", TIMEOUT_MS);
                    assertTrue(result);
                    successCount.incrementAndGet();
                } catch (TimeoutException | InterruptedException e) {
                    fail("Unexpected exception: " + e);
                }
            }));
        }

        startLatch.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        assertEquals(THREAD_COUNT, successCount.get());
    }

    @Test
    void concurrentMatchesProducesCorrectResults() throws Exception {
        Pattern pattern = Pattern.compile("^\\d{3}-\\d{3}-\\d{4}$");

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    boolean result = RegexUtils.matches(pattern, "123-456-7890", TIMEOUT_MS);
                    assertTrue(result);
                    successCount.incrementAndGet();
                } catch (TimeoutException | InterruptedException e) {
                    fail("Unexpected exception: " + e);
                }
            }));
        }

        startLatch.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        assertEquals(THREAD_COUNT, successCount.get());
    }

    // ---- ReDoS timeout tests ----

    // (.*a){25} causes exponential backtracking on input "aaa...ab" — the engine
    // tries every possible way to split 25 "a" characters across 25 groups, failing
    // because the trailing "b" cannot match "a" in the final repetition.
    private static final Pattern REDOS_CATASTROPHIC = Pattern.compile(REDOS_PATTERN);
    private static final String REDOS_TRIGGER = REDOS_INPUT;

    @Test
    void redosReplaceAllTimesOut() {
        Map<Pattern, String> replacements = new LinkedHashMap<>();
        replacements.put(REDOS_CATASTROPHIC, "replaced");

        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
            assertThrows(TimeoutException.class, () ->
                RegexUtils.replaceAll(REDOS_TRIGGER, replacements, TIMEOUT_MS)));
    }

    @Test
    void redosFindTimesOut() {
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
            assertThrows(TimeoutException.class, () ->
                RegexUtils.find(REDOS_CATASTROPHIC, REDOS_TRIGGER, TIMEOUT_MS)));
    }

    @Test
    void redosMatchesTimesOut() {
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
            assertThrows(TimeoutException.class, () ->
                RegexUtils.matches(REDOS_CATASTROPHIC, REDOS_TRIGGER, TIMEOUT_MS)));
    }

    @Test
    void redosConcurrentTimeoutsAreIsolated() throws Exception {
        Map<Pattern, String> replacements = new LinkedHashMap<>();
        replacements.put(REDOS_CATASTROPHIC, "replaced");

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger timeoutCount = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    RegexUtils.replaceAll(REDOS_TRIGGER, replacements, TIMEOUT_MS);
                    fail("Should have thrown TimeoutException");
                } catch (TimeoutException e) {
                    timeoutCount.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        startLatch.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        assertEquals(THREAD_COUNT, timeoutCount.get(),
                "All threads running ReDoS patterns should timeout independently");
    }

    // ---- Edge case tests ----

    @Test
    void negativeTimeoutThrowsIllegalArgumentException() {
        Map<Pattern, String> replacements = new LinkedHashMap<>();
        replacements.put(Pattern.compile("test"), "replaced");

        assertThrows(IllegalArgumentException.class, () ->
                RegexUtils.replaceAll("input", replacements, -1));
        assertThrows(IllegalArgumentException.class, () ->
                RegexUtils.find(Pattern.compile("test"), "input", -1));
        assertThrows(IllegalArgumentException.class, () ->
                RegexUtils.matches(Pattern.compile("test"), "input", -1));
    }

    @Test
    void nonTimeoutRuntimeExceptionPropagates() {
        // $3 references a capture group that doesn't exist in the pattern,
        // causing an IndexOutOfBoundsException inside replaceAll
        Map<Pattern, String> replacements = new LinkedHashMap<>();
        replacements.put(Pattern.compile("(test)"), "$3");

        assertThrows(IndexOutOfBoundsException.class, () ->
                RegexUtils.replaceAll("test", replacements, TIMEOUT_MS));
    }

    @Test
    void subSequencePreservesDeadline() throws TimeoutException {
        // Pattern with alternation forces the engine to call subSequence internally.
        // Verify the result is still correct (deadline is inherited, not reset).
        Pattern pattern = Pattern.compile("(ab|cd)+");
        boolean result = RegexUtils.find(pattern, "xxabcdabxx", TIMEOUT_MS);
        assertTrue(result);
    }

    @Test
    void nullReplacementsMapReturnsInputUnchanged() throws TimeoutException {
        String result = RegexUtils.replaceAll("unchanged", null, TIMEOUT_MS);
        assertEquals("unchanged", result);
    }
}
