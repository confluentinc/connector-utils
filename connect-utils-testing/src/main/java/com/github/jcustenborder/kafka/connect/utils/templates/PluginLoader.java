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
package com.github.jcustenborder.kafka.connect.utils.templates;


import com.github.jcustenborder.kafka.connect.utils.config.AnnotationHelper;
import com.github.jcustenborder.kafka.connect.utils.config.ConfigKeyComparator;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.apache.kafka.connect.connector.Connector;
import org.apache.kafka.connect.sink.SinkConnector;
import org.apache.kafka.connect.source.SourceConnector;
import org.apache.kafka.connect.storage.Converter;
import org.apache.kafka.connect.transforms.Transformation;
import org.reflections.Reflections;
import org.reflections.scanners.ResourcesScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class PluginLoader {
  static final Set<String> KEY_OR_VALUE = ImmutableSet.of("Key", "Value");
  static final String GENERAL_GROUP = "General";
  private static final Logger log = LoggerFactory.getLogger(PluginLoader.class);
  final Package pkg;
  final Reflections reflections;
  private List<Plugin.SourceConnector> sourceConnectors;
  private List<Plugin.SinkConnector> sinkConnectors;
  private List<Plugin.Transformation> transformations;
  private List<Plugin.Converter> converters;
  private List<Plugin.ConfigProvider> configProviders;
  private Set<String> allResources;

  public PluginLoader(Package pkg) {
    this.pkg = pkg;
    this.reflections = new Reflections(new ConfigurationBuilder()
        .setUrls(ClasspathHelper.forJavaClassPath())
        .forPackages(pkg.getName())
        .addScanners(new ResourcesScanner())
    );
  }

  ConfigDef transformationConfig(Class<? extends Transformation> transformation) {
    try {
      return transformation.newInstance().config();
    } catch (InstantiationException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  ConfigDef connectorConfig(Class<? extends Connector> connectorClass) {
    try {
      return connectorClass.newInstance().config();
    } catch (InstantiationException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  ConfigDef configConfig(Class<?> configClass) {
    ConfigDef result;
    if (!configClass.isAssignableFrom(Config.class)) {
      result = null;
    } else {
      try {
        Config config = (Config) configClass.newInstance();
        result = config.config();
      } catch (InstantiationException | IllegalAccessException e) {
        throw new IllegalStateException(e);
      }
    }
    return result;
  }


  ConfigDef configProvider(Class<? extends ConfigProvider> converterClass) {
    return configConfig(converterClass);
  }

  ConfigDef converterConfig(Class<? extends Converter> converterClass) {
    return configConfig(converterClass);
  }


  Set<Class<? extends Transformation>> findTransformations() {
    Set<Class<? extends Transformation>> transforms = this.reflections.getSubTypesOf(Transformation.class)
        .stream()
        .filter(c -> c.getName().startsWith(pkg.getName()))
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .filter(c -> !Modifier.isAbstract(c.getModifiers()))
        .filter((Predicate<Class<? extends Transformation>>) aClass -> Arrays.stream(aClass.getConstructors())
            .filter(c -> Modifier.isPublic(c.getModifiers()))
            .anyMatch(c -> c.getParameterCount() == 0))
        .sorted(Comparator.comparing(Class::getName))
        .collect(Collectors.toCollection(LinkedHashSet::new));
    final Set<Class<? extends Transformation>> result = new LinkedHashSet<>();


    for (Class<? extends Transformation> cls : transforms) {
      log.trace("findTransformations() - simpleName = '{}'", cls.getSimpleName());
      if (KEY_OR_VALUE.contains(cls.getSimpleName()) && null != cls.getDeclaringClass()) {
        result.add(cls.getDeclaringClass().asSubclass(Transformation.class));
      } else {
        result.add(cls);
      }
    }

    return result;
  }

  Set<Class<? extends SinkConnector>> findSinkConnectors() {
    return this.reflections.getSubTypesOf(SinkConnector.class)
        .stream()
        .filter(c -> c.getName().startsWith(pkg.getName()))
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .filter(c -> !Modifier.isAbstract(c.getModifiers()))
        .filter(aClass -> Arrays.stream(aClass.getConstructors())
            .filter(c -> Modifier.isPublic(c.getModifiers()))
            .anyMatch(c -> c.getParameterCount() == 0))
        .collect(Collectors.toSet());
  }

  Set<Class<? extends SourceConnector>> findSourceConnectors() {
    return this.reflections.getSubTypesOf(SourceConnector.class)
        .stream()
        .filter(c -> c.getName().startsWith(pkg.getName()))
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .filter(c -> !Modifier.isAbstract(c.getModifiers()))
        .filter(aClass -> Arrays.stream(aClass.getConstructors())
            .filter(c -> Modifier.isPublic(c.getModifiers()))
            .anyMatch(c -> c.getParameterCount() == 0))
        .collect(Collectors.toSet());
  }

  Set<Class<? extends Converter>> findConverters() {
    return this.reflections.getSubTypesOf(Converter.class)
        .stream()
        .filter(c -> c.getName().startsWith(pkg.getName()))
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .filter(c -> !Modifier.isAbstract(c.getModifiers()))
        .filter(aClass -> Arrays.stream(aClass.getConstructors())
            .filter(c -> Modifier.isPublic(c.getModifiers()))
            .anyMatch(c -> c.getParameterCount() == 0))
        .collect(Collectors.toSet());
  }

  Set<Class<? extends ConfigProvider>> findConfigProviders() {
    return this.reflections.getSubTypesOf(ConfigProvider.class)
        .stream()
        .filter(c -> c.getName().startsWith(pkg.getName()))
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .filter(c -> !Modifier.isAbstract(c.getModifiers()))
        .filter(aClass -> Arrays.stream(aClass.getConstructors())
            .filter(c -> Modifier.isPublic(c.getModifiers()))
            .anyMatch(c -> c.getParameterCount() == 0))
        .collect(Collectors.toSet());
  }

  Plugin.Configuration config(ConfigDef config) {
    ImmutableConfiguration.Builder configBuilder = ImmutableConfiguration.builder();
    Map<String, ImmutableGroup.Builder> groupBuilderCache = new LinkedHashMap<>();
    List<ConfigDef.ConfigKey> configKeys = config.configKeys().values()
        .stream()
        .sorted(ConfigKeyComparator.INSTANCE)
        .collect(Collectors.toList());

    for (ConfigDef.ConfigKey configKey : configKeys) {
      final String group = Strings.isNullOrEmpty(configKey.group) ? GENERAL_GROUP : configKey.group;
      Plugin.Item item = ImmutableItem.builder()
          .defaultValue(ConfigDef.NO_DEFAULT_VALUE.equals(configKey.defaultValue) ? null : configKey.defaultValue)
          .doc(configKey.documentation)
          .group(group)
          .importance(configKey.importance)
          .isRequired(!configKey.hasDefault())
          .name(configKey.name)
          .type(configKey.type)
          .validator(configKey.validator)
          .build();

      ImmutableGroup.Builder groupBuilder = groupBuilderCache.computeIfAbsent(group, (Function<String, ImmutableGroup.Builder>) s -> ImmutableGroup.builder().name(group));
      groupBuilder.addItems(item);
      if (item.isRequired()) {
        configBuilder.addRequiredConfigs(item);
      }
    }

    groupBuilderCache.values()
        .stream()
        .map(ImmutableGroup.Builder::build)
        .forEach(configBuilder::addGroups);

    return configBuilder.build();
  }

  public Plugin load() {
    ImmutablePlugin.Builder builder = ImmutablePlugin.builder()
        .from(notes(this.pkg))
        .pluginName(AnnotationHelper.pluginName(this.pkg))
        .pluginOwner(AnnotationHelper.pluginOwner(this.pkg));
    List<Plugin.Transformation> transformations = loadTransformations();
    builder.addAllTransformations(transformations);
    List<Plugin.SinkConnector> sinkConnectors = loadSinkConnectors();
    builder.addAllSinkConnectors(sinkConnectors);
    List<Plugin.SourceConnector> sourceConnectors = loadSourceConnectors();
    builder.addAllSourceConnectors(sourceConnectors);
    List<Plugin.Converter> converters = loadConverters();
    builder.addAllConverters(converters);
    List<Plugin.ConfigProvider> configProviders = loadConfigProviders();
    builder.addAllConfigProviders(configProviders);
    return builder.build();
  }

  private List<Plugin.Converter> loadConverters() {
    if (null != this.converters) {
      return this.converters;
    }
    List<Plugin.Converter> result = new ArrayList<>();
    Set<Class<? extends Converter>> converters = findConverters();

    for (Class<? extends Converter> cls : converters) {
      log.trace("loadConverters() - processing {}", cls.getName());
      ImmutableConverter.Builder builder = ImmutableConverter.builder()
          .cls(cls)
          .from(notes(cls));
      ConfigDef configDef = converterConfig(cls);
      if (null != configDef) {
        Plugin.Configuration configuration = config(configDef);
        builder.configuration(configuration);
      }
      result.add(builder.build());
    }

    return (this.converters = result);
  }

  private List<Plugin.ConfigProvider> loadConfigProviders() {
    if (null != this.configProviders) {
      return this.configProviders;
    }
    List<Plugin.ConfigProvider> result = new ArrayList<>();
    Set<Class<? extends ConfigProvider>> configProviders = findConfigProviders();

    for (Class<? extends ConfigProvider> cls : configProviders) {
      log.trace("loadConfigProviders() - processing {}", cls.getName());
      ImmutableConfigProvider.Builder builder = ImmutableConfigProvider.builder()
          .cls(cls)
          .from(notes(cls));
      ConfigDef configDef = configProvider(cls);

      if (null != configDef) {
        Plugin.Configuration configuration = config(configDef);
        builder.configuration(configuration);
      }

      result.add(builder.build());
    }

    return (this.configProviders = result);
  }


  private List<Plugin.SourceConnector> loadSourceConnectors() {
    if (null != this.sourceConnectors) {
      return this.sourceConnectors;
    }
    List<Plugin.SourceConnector> result = new ArrayList<>();
    Set<Class<? extends SourceConnector>> sourceConnectors = findSourceConnectors();

    for (Class<? extends SourceConnector> cls : sourceConnectors) {
      log.trace("loadSourceConnectors() - processing {}", cls.getName());
      ConfigDef configDef = connectorConfig(cls);
      Plugin.Configuration configuration = config(configDef);
      ImmutableSourceConnector.Builder builder = ImmutableSourceConnector.builder()
          .cls(cls)
          .configuration(configuration)
          .from(notes(cls));
      List<String> examples = findExamples(cls);
      builder.addAllExamples(examples);
      result.add(builder.build());
    }

    return (this.sourceConnectors = result);
  }

  private List<Plugin.SinkConnector> loadSinkConnectors() {
    if (null != this.sinkConnectors) {
      return this.sinkConnectors;
    }

    List<Plugin.SinkConnector> result = new ArrayList<>();
    Set<Class<? extends SinkConnector>> sinkConnectors = findSinkConnectors();

    for (Class<? extends SinkConnector> cls : sinkConnectors) {
      log.trace("loadSinkConnectors() - processing {}", cls.getName());
      ConfigDef configDef = connectorConfig(cls);
      Plugin.Configuration configuration = config(configDef);
      ImmutableSinkConnector.Builder builder = ImmutableSinkConnector.builder()
          .cls(cls)
          .configuration(configuration)
          .from(notes(cls));
      List<String> examples = findExamples(cls);
      builder.addAllExamples(examples);
      result.add(builder.build());
    }

    return (this.sinkConnectors = result);
  }

  private List<Plugin.Transformation> loadTransformations() {
    if (null != this.transformations) {
      return this.transformations;
    }
    List<Plugin.Transformation> result = new ArrayList<>();
    Set<Class<? extends Transformation>> tranformations = findTransformations();

    for (Class<? extends Transformation> cls : tranformations) {
      log.trace("loadTransformations() - processing {}", cls.getName());
      ImmutableTransformation.Builder builder = ImmutableTransformation.builder()
          .cls(cls)
          .from(notes(cls));
      Class[] classes = cls.getClasses();
      boolean isKeyValue = false;
      Class keyClass = null;
      Class valueClass = null;

      if (null != classes) {
        for (Class c : classes) {
          if ("Key".equals(c.getSimpleName())) {
            keyClass = c;
            isKeyValue = true;
          } else if ("Value".equals(c.getSimpleName())) {
            isKeyValue = true;
            valueClass = c;
          }
        }
      } else {
        isKeyValue = false;
      }
      builder.isKeyValue(isKeyValue);
      if (null != keyClass) {
        builder.key(keyClass);
      }
      if (null != valueClass) {
        builder.value(valueClass);
      }
      ConfigDef configDef;
      if (isKeyValue) {
        if (null != keyClass) {
          configDef = transformationConfig(keyClass);
        } else if (null != valueClass) {
          configDef = transformationConfig(valueClass);
        } else {
          throw new IllegalStateException("key and value class null");
        }
      } else {
        configDef = transformationConfig(cls);
      }
      Plugin.Configuration configuration = config(configDef);
      builder.configuration(configuration);

      List<String> examples = findExamples(cls);
      builder.addAllExamples(examples);

      result.add(builder.build());
    }

    return (this.transformations = result);
  }

  private Set<String> allResources() {
    Set<String> result;
    if (null == allResources) {
      result = (this.allResources = this.reflections.getResources(s -> s.endsWith(".json")));
    } else {
      result = allResources;
    }

    return result;
  }

  private List<String> findExamples(Class<?> cls) {
    final String examplePrefix = cls.getName().replace('.', '/') + "/";
    log.trace("findExamples() - Searching for examples for '{}' with '{}'", cls.getName(), examplePrefix);
    return this.allResources().stream()
        .filter(s -> s.startsWith(examplePrefix))
        .map(e -> "/" + e)
        .collect(Collectors.toList());
  }


  private Notes notes(Class cls) {
    ImmutableCopy.Builder builder = ImmutableCopy.builder();
    builder.description(AnnotationHelper.description(cls));
    builder.danger(AnnotationHelper.danger(cls));
    builder.important(AnnotationHelper.important(cls));
    builder.note(AnnotationHelper.note(cls));
    builder.tip(AnnotationHelper.tip(cls));
    builder.title(AnnotationHelper.title(cls));
    builder.warning(AnnotationHelper.warning(cls));
    return builder.build();
  }

  private Notes notes(Package pkg) {
    ImmutableCopy.Builder builder = ImmutableCopy.builder();
    builder.danger(AnnotationHelper.danger(pkg));
    builder.important(AnnotationHelper.important(pkg));
    builder.note(AnnotationHelper.note(pkg));
    builder.tip(AnnotationHelper.tip(pkg));
    builder.introduction(AnnotationHelper.introduction(pkg));
    builder.title(AnnotationHelper.title(pkg));
    builder.warning(AnnotationHelper.warning(pkg));
    return builder.build();
  }
}
